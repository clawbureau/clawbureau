import * as fs from 'fs';
import * as crypto from 'crypto';
import * as readline from 'readline';

export interface DecryptedConnection {
  fd: number;
  clientRandom: string;            // hex
  hostname: string;                // from tls_sni event
  cipherSuite: string;             // e.g. 'TLS_AES_128_GCM_SHA256'
  recordsDecrypted: number;
  bytesTx: number;
  bytesRx: number;
}

export interface DecryptedRequest {
  fd: number;
  streamId: number;
  method: string;
  path: string;
  authority: string;
  model: string;                   // from request body or response header
  requestBodyHash: string;         // SHA-256 base64url
  responseBodyHash: string;        // SHA-256 base64url
  tokensInput: number;
  tokensOutput: number;
  latencyMs: number;
  timestamp: string;               // ISO 8601
}

export interface GatewayReceiptPayload {
  receipt_version: '1';
  receipt_id: string;          // crypto.randomUUID()
  gateway_id: string;          // 'clawsig-interpose'
  provider: string;            // 'anthropic' | 'openai' | 'google' | etc (from :authority)
  model: string;               // From request JSON 'model' field or x-model response header
  request_hash_b64u: string;   // SHA-256 of request body bytes, base64url
  response_hash_b64u: string;  // SHA-256 of response body bytes, base64url
  tokens_input: number;        // From response JSON usage.input_tokens or usage.prompt_tokens
  tokens_output: number;       // From response JSON usage.output_tokens or usage.completion_tokens
  latency_ms: number;          // From spool timestamps: first DATA on response stream - last DATA on request stream
  timestamp: string;           // ISO 8601
}

export interface DecryptResult {
  connections: DecryptedConnection[];
  requests: DecryptedRequest[];
  receipts: GatewayReceiptPayload[];
  errors: string[];
}

// --- HKDF Implementation ---

function hkdfExpand(prk: Buffer, info: Buffer, length: number): Buffer {
  const hashLen = 32; // SHA-256
  const n = Math.ceil(length / hashLen);
  const okm = Buffer.alloc(n * hashLen);
  let prev = Buffer.alloc(0);
  for (let i = 1; i <= n; i++) {
    const hmac = crypto.createHmac('sha256', prk);
    hmac.update(prev);
    hmac.update(info);
    hmac.update(Buffer.from([i]));
    prev = hmac.digest();
    prev.copy(okm, (i - 1) * hashLen);
  }
  return okm.subarray(0, length);
}

function hkdfExpandLabel(secret: Buffer, label: string, context: Buffer, length: number): Buffer {
  const fullLabel = `tls13 ${label}`;
  const info = Buffer.alloc(2 + 1 + fullLabel.length + 1 + context.length);
  info.writeUInt16BE(length, 0);
  info[2] = fullLabel.length;
  info.write(fullLabel, 3, 'ascii');
  info[3 + fullLabel.length] = context.length;
  if (context.length > 0) context.copy(info, 4 + fullLabel.length);
  return hkdfExpand(secret, info, length);
}

// --- Decryption Logic ---

function tryDecrypt(key: Buffer, iv: Buffer, seqNum: bigint, record: Buffer, aad: Buffer,
                    algorithm: string): Buffer | null {
  // Build nonce: iv XOR padded sequence number
  const nonce = Buffer.alloc(12);
  iv.copy(nonce);
  const seqBuf = Buffer.alloc(12);
  seqBuf.writeBigUInt64BE(seqNum, 4); // right-aligned in 12 bytes
  for (let i = 0; i < 12; i++) nonce[i] ^= seqBuf[i];

  // Split ciphertext and tag
  const ciphertext = record.subarray(0, record.length - 16);
  const tag = record.subarray(record.length - 16);

  try {
    const decipher: any = crypto.createDecipheriv(algorithm, key, nonce, { authTagLength: 16 } as any);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    // Use concat to ensure we get the full plaintext if updated in chunks (though here it's one buffer)
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext;
  } catch {
    return null; // Wrong cipher suite — tag mismatch
  }
}

// --- HTTP/2 HPACK & Frame Parsing ---

// Simplified HPACK integer decoding
function decodeInteger(buf: Buffer, offset: number, N: number): { value: number, len: number } {
  let byte = buf[offset];
  const mask = (1 << N) - 1;
  let value = byte & mask;
  if (value < mask) {
    return { value, len: 1 };
  }
  let i = 1;
  let shift = 0;
  while (offset + i < buf.length) {
    byte = buf[offset + i];
    value += (byte & 127) * (1 << shift);
    i++;
    shift += 7;
    if ((byte & 128) === 0) break;
  }
  return { value, len: i };
}

// Minimal header parser
function parseH2Headers(payload: Buffer): Record<string, string> {
  const headers: Record<string, string> = {};
  let offset = 0;
  while (offset < payload.length) {
    const byte = payload[offset];
    if ((byte & 0x80) !== 0) {
      // Indexed Header Field
      const { value: index, len } = decodeInteger(payload, offset, 7);
      offset += len;
      if (index === 2) headers[':method'] = 'GET';
      else if (index === 3) headers[':method'] = 'POST';
      else if (index === 6) headers[':scheme'] = 'http';
      else if (index === 7) headers[':scheme'] = 'https';
      else if (index === 8) headers[':status'] = '200';
    } else {
      // Literal header field - skip for now as per minimal implementation request
      // (Proper implementation requires Huffman decoding which is too large to inline)
      // Consume one byte to prevent infinite loop if payload isn't fully parsed
      offset++; 
      // In real implementation we would decode string length and skip string
    }
  }
  return headers;
}

// --- Main Implementation ---

export async function decryptTraffic(
  tracePath: string,
  keylogPath?: string,
  cipherPath?: string,
): Promise<DecryptResult> {
  const finalKeylogPath = keylogPath || `${tracePath}.keys`;
  const finalCipherPath = cipherPath || `${tracePath}.clawcipher`;

  const result: DecryptResult = {
    connections: [],
    requests: [],
    receipts: [],
    errors: [],
  };

  // 1. Read Trace (JSONL) to map fd -> client_random, hostname
  const fdMap = new Map<number, { clientRandom: string; hostname?: string }>();
  
  if (fs.existsSync(tracePath)) {
    const fileStream = fs.createReadStream(tracePath);
    const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });
    for await (const line of rl) {
      if (!line.trim()) continue;
      try {
        const event = JSON.parse(line);
        if (event.layer === 'interpose') {
          if (event.syscall === 'tls_client_hello' && event.client_random) {
            const existing = fdMap.get(event.fd) || { clientRandom: '' };
            existing.clientRandom = event.client_random;
            fdMap.set(event.fd, existing);
          } else if (event.syscall === 'tls_sni' && event.hostname) {
            const existing = fdMap.get(event.fd) || { clientRandom: '' };
            existing.hostname = event.hostname;
            fdMap.set(event.fd, existing);
          }
        }
      } catch {}
    }
  }

  // 2. Read Keylog to map client_random -> secrets
  const secretsMap = new Map<string, { clientSecret: string; serverSecret: string }>();
  
  if (fs.existsSync(finalKeylogPath)) {
    const fileStream = fs.createReadStream(finalKeylogPath);
    const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });
    for await (const line of rl) {
      const parts = line.split(' ');
      if (parts.length < 3) continue;
      const label = parts[0];
      const clientRandom = parts[1];
      const secret = parts[2];
      
      if (!secretsMap.has(clientRandom)) {
        secretsMap.set(clientRandom, { clientSecret: '', serverSecret: '' });
      }
      const entry = secretsMap.get(clientRandom)!;
      
      if (label === 'CLIENT_TRAFFIC_SECRET_0') entry.clientSecret = secret;
      if (label === 'SERVER_TRAFFIC_SECRET_0') entry.serverSecret = secret;
    }
  }

  // 3. Process Cipher Spool
  if (!fs.existsSync(finalCipherPath)) {
    result.errors.push(`Cipher spool not found: ${finalCipherPath}`);
    return result;
  }

  const spool = await fs.promises.readFile(finalCipherPath);
  let offset = 0;
  
  interface ConnectionState {
    fd: number;
    clientRandom: string;
    hostname: string;
    secrets: { clientSecret: Buffer; serverSecret: Buffer };
    cipherSuite: string;
    clientKey: Buffer; clientIv: Buffer; clientSeq: bigint;
    serverKey: Buffer; serverIv: Buffer; serverSeq: bigint;
    bufferTx: Buffer; // TCP reassembly buffer
    bufferRx: Buffer;
    lastHashTx: string; // Deduplication
    lastHashRx: string;
    h2StateTx: { buffer: Buffer }; // HTTP/2 frame reassembly
    h2StateRx: { buffer: Buffer };
    streams: Map<number, { req: Partial<DecryptedRequest>, res: Partial<DecryptedRequest>, reqBody: Buffer, resBody: Buffer, reqTime?: number, resTime?: number }>;
  }

  const connections = new Map<number, ConnectionState>();

  while (offset < spool.length) {
    if (offset + 17 > spool.length) break; // Incomplete header

    const timestamp = spool.readBigUInt64LE(offset); // nanoseconds
    const fd = spool.readUInt32LE(offset + 8);
    const direction = spool.readUInt8(offset + 12); // 0=TX, 1=RX
    const payloadLen = spool.readUInt32LE(offset + 13);
    const payload = spool.subarray(offset + 17, offset + 17 + payloadLen);
    offset += 17 + payloadLen;

    // Deduplication
    const payloadHash = crypto.createHash('sha256').update(payload).digest('hex');
    
    // Initialize connection state if needed
    if (!connections.has(fd)) {
      const meta = fdMap.get(fd);
      if (!meta || !meta.clientRandom) continue; // No metadata, can't decrypt
      
      const secrets = secretsMap.get(meta.clientRandom);
      if (!secrets || !secrets.clientSecret || !secrets.serverSecret) continue; // No secrets

      connections.set(fd, {
        fd,
        clientRandom: meta.clientRandom,
        hostname: meta.hostname || 'unknown',
        secrets: {
          clientSecret: Buffer.from(secrets.clientSecret, 'hex'),
          serverSecret: Buffer.from(secrets.serverSecret, 'hex')
        },
        cipherSuite: '', // Determined on first packet
        clientKey: Buffer.alloc(0), clientIv: Buffer.alloc(0), clientSeq: 0n,
        serverKey: Buffer.alloc(0), serverIv: Buffer.alloc(0), serverSeq: 0n,
        bufferTx: Buffer.alloc(0),
        bufferRx: Buffer.alloc(0),
        lastHashTx: '',
        lastHashRx: '',
        h2StateTx: { buffer: Buffer.alloc(0) },
        h2StateRx: { buffer: Buffer.alloc(0) },
        streams: new Map(),
      });
    }

    const conn = connections.get(fd)!;
    
    // Check dupe
    if (direction === 0) {
      if (conn.lastHashTx === payloadHash) continue;
      conn.lastHashTx = payloadHash;
      conn.bufferTx = Buffer.concat([conn.bufferTx, payload]);
    } else {
      if (conn.lastHashRx === payloadHash) continue;
      conn.lastHashRx = payloadHash;
      conn.bufferRx = Buffer.concat([conn.bufferRx, payload]);
    }

    // Attempt to process TCP stream for TLS records
    processTlsRecords(conn, direction, Number(timestamp));
  }

  // Finalize receipts
  for (const conn of connections.values()) {
    result.connections.push({
      fd: conn.fd,
      clientRandom: conn.clientRandom,
      hostname: conn.hostname,
      cipherSuite: conn.cipherSuite,
      recordsDecrypted: Number(conn.clientSeq + conn.serverSeq),
      bytesTx: conn.bufferTx.length, // Rough estimate remaining
      bytesRx: conn.bufferRx.length,
    });

    for (const [streamId, stream] of conn.streams.entries()) {
      if (stream.req && stream.req.method) { // Valid request
        const reqBodyHash = crypto.createHash('sha256').update(stream.reqBody || Buffer.alloc(0)).digest('base64url');
        const resBodyHash = crypto.createHash('sha256').update(stream.resBody || Buffer.alloc(0)).digest('base64url');

        // Extract model/tokens from JSON bodies
        let model = stream.req.model || 'unknown';
        let tokensIn = 0;
        let tokensOut = 0;

        try {
          if (stream.reqBody && stream.reqBody.length > 0) {
            const json = JSON.parse(stream.reqBody.toString());
            if (json.model) model = json.model;
          }
        } catch {}

        try {
          if (stream.resBody && stream.resBody.length > 0) {
            // Check for SSE "data: " prefix or raw JSON
            const text = stream.resBody.toString();
            if (text.startsWith('data: ')) {
               // SSE parsing: look for final usage block
               const lines = text.split('\n');
               for (const line of lines) {
                 if (line.startsWith('data: ') && line !== 'data: [DONE]') {
                   try {
                     const json = JSON.parse(line.substring(6));
                     if (json.usage) {
                       tokensIn = json.usage.input_tokens || json.usage.prompt_tokens || 0;
                       tokensOut = json.usage.output_tokens || json.usage.completion_tokens || 0;
                     }
                     if (json.model) model = json.model; // Update model from response if available
                   } catch {}
                 }
               }
            } else {
               const json = JSON.parse(text);
               if (json.usage) {
                 tokensIn = json.usage.input_tokens || json.usage.prompt_tokens || 0;
                 tokensOut = json.usage.output_tokens || json.usage.completion_tokens || 0;
               }
               if (json.model) model = json.model;
            }
          }
        } catch {}

        const latency = (stream.resTime && stream.reqTime) ? (stream.resTime - stream.reqTime) / 1e6 : 0; // ns to ms

        const receipt: GatewayReceiptPayload = {
          receipt_version: '1',
          receipt_id: crypto.randomUUID(),
          gateway_id: 'clawsig-interpose',
          provider: conn.hostname, // Simple mapping
          model,
          request_hash_b64u: reqBodyHash,
          response_hash_b64u: resBodyHash,
          tokens_input: tokensIn,
          tokens_output: tokensOut,
          latency_ms: Math.round(latency),
          timestamp: new Date().toISOString(),
        };

        result.receipts.push(receipt);
        
        result.requests.push({
          fd: conn.fd,
          streamId,
          method: stream.req.method || 'UNKNOWN',
          path: stream.req.path || 'UNKNOWN',
          authority: stream.req.authority || conn.hostname,
          model,
          requestBodyHash: reqBodyHash,
          responseBodyHash: resBodyHash,
          tokensInput: tokensIn,
          tokensOutput: tokensOut,
          latencyMs: Math.round(latency),
          timestamp: receipt.timestamp,
        });
      }
    }
  }

  return result;
}

function processTlsRecords(conn: any, direction: number, timestamp: number) {
  const buffer = direction === 0 ? conn.bufferTx : conn.bufferRx;
  let offset = 0;

  // TLS Record Header: Type(1) + Ver(2) + Len(2) = 5 bytes
  while (offset + 5 <= buffer.length) {
    const contentType = buffer[offset];
    // const version = buffer.readUInt16BE(offset + 1);
    const length = buffer.readUInt16BE(offset + 3);

    if (offset + 5 + length > buffer.length) break; // Incomplete record

    const record = buffer.subarray(offset + 5, offset + 5 + length);
    // AAD is the 5-byte header
    const aad = buffer.subarray(offset, offset + 5);

    offset += 5 + length;

    // Handle initial setup / cipher suite detection
    if (!conn.cipherSuite) {
      // Try to detect cipher suite on first App Data (0x17) record
      if (contentType === 0x17) {
         if (deriveAndTestCipher(conn, record, aad, 0n, direction)) {
           // Success
         } else {
           // Failed to decrypt first record
           continue; 
         }
      } else {
        // Skip plaintext handshake messages (0x16) or others
        continue;
      }
    }

    if (contentType === 0x17) {
      // Decrypt
      // const secret = direction === 0 ? conn.secrets.clientSecret : conn.secrets.serverSecret;
      const key = direction === 0 ? conn.clientKey : conn.serverKey;
      const iv = direction === 0 ? conn.clientIv : conn.serverIv;
      const seq = direction === 0 ? conn.clientSeq : conn.serverSeq;
      
      // Select algo
      let algo = '';
      if (conn.cipherSuite === 'TLS_AES_128_GCM_SHA256') algo = 'aes-128-gcm';
      else if (conn.cipherSuite === 'TLS_CHACHA20_POLY1305_SHA256') algo = 'chacha20-poly1305';
      else if (conn.cipherSuite === 'TLS_AES_256_GCM_SHA384') algo = 'aes-256-gcm';
      
      const plaintext = tryDecrypt(key, iv, seq, record, aad, algo);
      
      if (plaintext) {
        // Increment seq
        if (direction === 0) conn.clientSeq++; else conn.serverSeq++;
        
        // Strip inner content type
        let end = plaintext.length - 1;
        while (end >= 0 && plaintext[end] === 0) end--;
        const innerType = plaintext[end];
        const actualData = plaintext.subarray(0, end);
        
        if (innerType === 0x17) {
          // HTTP/2 Frame Processing
          processH2Frames(conn, direction, actualData, timestamp);
        }
      }
    }
  }

  // Update buffer
  if (direction === 0) conn.bufferTx = buffer.subarray(offset);
  else conn.bufferRx = buffer.subarray(offset);
}

function deriveAndTestCipher(conn: any, record: Buffer, aad: Buffer, seq: bigint, direction: number): boolean {
  // Try candidates
  const candidates = [
    { suite: 'TLS_AES_128_GCM_SHA256', keyLen: 16, algo: 'aes-128-gcm' },
    { suite: 'TLS_CHACHA20_POLY1305_SHA256', keyLen: 32, algo: 'chacha20-poly1305' },
    { suite: 'TLS_AES_256_GCM_SHA384', keyLen: 32, algo: 'aes-256-gcm' },
  ];

  for (const cand of candidates) {
    // Derive keys
    const secret = direction === 0 ? conn.secrets.clientSecret : conn.secrets.serverSecret;
    // Note: If secret is 32 bytes, can't be AES-256 (SHA-384). 
    // We assume standard SHA-256 secrets for now as per prompt example.
    
    const key = hkdfExpandLabel(secret, 'key', Buffer.alloc(0), cand.keyLen);
    const iv = hkdfExpandLabel(secret, 'iv', Buffer.alloc(0), 12);
    
    const plain = tryDecrypt(key, iv, seq, record, aad, cand.algo);
    if (plain) {
      // Found it!
      conn.cipherSuite = cand.suite;
      
      // Set keys for BOTH directions (assuming same suite)
      conn.clientKey = hkdfExpandLabel(conn.secrets.clientSecret, 'key', Buffer.alloc(0), cand.keyLen);
      conn.clientIv = hkdfExpandLabel(conn.secrets.clientSecret, 'iv', Buffer.alloc(0), 12);
      
      conn.serverKey = hkdfExpandLabel(conn.secrets.serverSecret, 'key', Buffer.alloc(0), cand.keyLen);
      conn.serverIv = hkdfExpandLabel(conn.secrets.serverSecret, 'iv', Buffer.alloc(0), 12);
      
      return true;
    }
  }
  return false;
}

function processH2Frames(conn: any, direction: number, data: Buffer, timestamp: number) {
  const state = direction === 0 ? conn.h2StateTx : conn.h2StateRx;
  
  // Skip Client Connection Preface if present (24 bytes)
  if (direction === 0 && data.length >= 24 && data.toString('ascii').startsWith('PRI * HTTP/2.0')) {
     data = data.subarray(24);
  }
  
  state.buffer = Buffer.concat([state.buffer, data]);
  
  let offset = 0;
  // Frame Header: Len(3) + Type(1) + Flags(1) + StreamID(4) = 9 bytes
  while (offset + 9 <= state.buffer.length) {
    const lenHi = state.buffer.readUInt16BE(offset);
    const lenLo = state.buffer[offset + 2];
    const length = (lenHi << 8) | lenLo;
    const type = state.buffer[offset + 3];
    // const flags = state.buffer[offset + 4];
    const streamId = state.buffer.readUInt32BE(offset + 5) & 0x7FFFFFFF;
    
    if (offset + 9 + length > state.buffer.length) break;
    
    const payload = state.buffer.subarray(offset + 9, offset + 9 + length);
    offset += 9 + length;

    // Process Frame
    if (!conn.streams.has(streamId)) {
      conn.streams.set(streamId, { req: {}, res: {}, reqBody: Buffer.alloc(0), resBody: Buffer.alloc(0) });
    }
    const stream = conn.streams.get(streamId);

    if (type === 0x01) { // HEADERS
       const headers = parseH2Headers(payload);
       
       if (direction === 0) { // Request
         if (headers[':method']) stream.req.method = headers[':method'];
         if (headers[':path']) stream.req.path = headers[':path'];
         if (headers[':authority']) stream.req.authority = headers[':authority'];
         if (!stream.reqTime) stream.reqTime = timestamp;
       } else { // Response
         if (headers[':status']) stream.res.status = headers[':status'];
         if (headers['x-model']) stream.res.model = headers['x-model'];
         if (headers['openai-model']) stream.res.model = headers['openai-model'];
         if (!stream.resTime) stream.resTime = timestamp;
       }
    } else if (type === 0x00) { // DATA
       if (direction === 0) {
         stream.reqBody = Buffer.concat([stream.reqBody, payload]);
         stream.reqTime = timestamp;
       } else {
         stream.resBody = Buffer.concat([stream.resBody, payload]);
         if (!stream.resTime || stream.resTime > timestamp) stream.resTime = timestamp;
       }
    }
  }
  
  state.buffer = state.buffer.subarray(offset);
}
