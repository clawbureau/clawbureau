#!/usr/bin/env node

/**
 * Smoke test: clawea Control UI WebSocket (control-session auth)
 *
 * Validates the end-to-end path:
 *   1) Tenant auth can mint a short-lived Control UI session token
 *   2) Cookie-based session authenticates the WS proxy (no tenant API key in browser)
 *   3) WS connect succeeds even if the client omits auth.password
 *      (clawea proxy injects the gateway password server-side)
 *
 * Usage:
 *   CLAWEA_TENANT_KEY=... node scripts/clawea/smoke-controlui-ws.mjs --env staging --agent <agentId>
 *   CLAWEA_TENANT_KEY=... node scripts/clawea/smoke-controlui-ws.mjs --env prod --agent <agentId>
 *
 * Optional:
 *   --base-url <url>   Override base URL (defaults to https://clawea.com[/staging])
 */

import process from 'node:process';
import tls from 'node:tls';
import crypto from 'node:crypto';
import dns from 'node:dns/promises';

function parseArgs(argv) {
  const args = new Map();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next && !next.startsWith('--')) {
      args.set(key, next);
      i++;
    } else {
      args.set(key, 'true');
    }
  }
  return args;
}

function assert(cond, msg) {
  if (!cond) throw new Error(`ASSERT_FAILED: ${msg}`);
}

function isRecord(x) {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

async function httpJson(url, init) {
  const res = await fetch(url, init);
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { res, status: res.status, text, json };
}

function encodeClientTextFrame(text) {
  const payload = Buffer.from(text, 'utf8');

  // FIN + text opcode
  const b0 = 0x80 | 0x1;

  const maskKey = crypto.randomBytes(4);

  let header;
  if (payload.length <= 125) {
    header = Buffer.alloc(2);
    header[0] = b0;
    header[1] = 0x80 | payload.length; // MASK bit set
  } else if (payload.length <= 0xffff) {
    header = Buffer.alloc(4);
    header[0] = b0;
    header[1] = 0x80 | 126;
    header.writeUInt16BE(payload.length, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = b0;
    header[1] = 0x80 | 127;
    // Only supporting up to 2^32-1 bytes here (plenty for our smoke frames)
    header.writeUInt32BE(0, 2);
    header.writeUInt32BE(payload.length, 6);
  }

  const masked = Buffer.alloc(payload.length);
  for (let i = 0; i < payload.length; i++) {
    masked[i] = payload[i] ^ maskKey[i % 4];
  }

  return Buffer.concat([header, maskKey, masked]);
}

function encodeClientControlFrame(opcode, payload = Buffer.alloc(0)) {
  // FIN + opcode
  const b0 = 0x80 | (opcode & 0x0f);
  const maskKey = crypto.randomBytes(4);

  assert(payload.length <= 125, 'Control frames must be <=125 bytes');

  const header = Buffer.alloc(2);
  header[0] = b0;
  header[1] = 0x80 | payload.length;

  const masked = Buffer.alloc(payload.length);
  for (let i = 0; i < payload.length; i++) masked[i] = payload[i] ^ maskKey[i % 4];

  return Buffer.concat([header, maskKey, masked]);
}

function tryParseServerFrame(buf) {
  if (buf.length < 2) return null;

  const b0 = buf[0];
  const b1 = buf[1];

  const opcode = b0 & 0x0f;
  const masked = (b1 & 0x80) !== 0;
  let len = b1 & 0x7f;

  let offset = 2;

  if (len === 126) {
    if (buf.length < offset + 2) return null;
    len = buf.readUInt16BE(offset);
    offset += 2;
  } else if (len === 127) {
    if (buf.length < offset + 8) return null;
    const hi = buf.readUInt32BE(offset);
    const lo = buf.readUInt32BE(offset + 4);
    offset += 8;
    assert(hi === 0, 'Frame too large for this smoke client');
    len = lo;
  }

  let maskKey = null;
  if (masked) {
    if (buf.length < offset + 4) return null;
    maskKey = buf.subarray(offset, offset + 4);
    offset += 4;
  }

  if (buf.length < offset + len) return null;

  let payload = buf.subarray(offset, offset + len);
  offset += len;

  if (masked && maskKey) {
    const out = Buffer.alloc(payload.length);
    for (let i = 0; i < payload.length; i++) out[i] = payload[i] ^ maskKey[i % 4];
    payload = out;
  }

  return {
    opcode,
    payload,
    rest: buf.subarray(offset),
  };
}

async function writeAll(socket, buf) {
  await new Promise((resolve, reject) => {
    socket.write(buf, (err) => (err ? reject(err) : resolve()));
  });
}

async function readUntil(socket, delimiter, initial = Buffer.alloc(0)) {
  let buf = initial;
  while (true) {
    const idx = buf.indexOf(delimiter);
    if (idx !== -1) {
      return {
        head: buf.subarray(0, idx + delimiter.length),
        rest: buf.subarray(idx + delimiter.length),
      };
    }

    const chunk = await new Promise((resolve, reject) => {
      socket.once('data', resolve);
      socket.once('error', reject);
      socket.once('end', () => reject(new Error('socket_end')));
    });

    buf = Buffer.concat([buf, chunk]);
  }
}

function parseHttpResponseHead(headBuf) {
  const text = headBuf.toString('utf8');
  const lines = text.split('\r\n');
  const statusLine = lines[0] || '';
  const m = statusLine.match(/^HTTP\/[0-9.]+\s+(\d{3})\b/);
  const status = m ? Number(m[1]) : 0;

  /** @type {Map<string,string>} */
  const headers = new Map();
  for (const line of lines.slice(1)) {
    if (!line) continue;
    const i = line.indexOf(':');
    if (i === -1) continue;
    const k = line.slice(0, i).trim().toLowerCase();
    const v = line.slice(i + 1).trim();
    headers.set(k, v);
  }

  return { status, headers, raw: text };
}

async function openWebSocket({ host, path, origin, cookieToken }) {
  const addrs = await dns.resolve4(host);
  assert(addrs.length > 0, `No IPv4 addresses for host: ${host}`);
  const ip = addrs[0];

  const socket = tls.connect({
    host: ip,
    port: 443,
    servername: host,
    ALPNProtocols: ['http/1.1'],
  });

  await new Promise((resolve, reject) => {
    socket.once('secureConnect', resolve);
    socket.once('error', reject);
  });

  const wsKey = crypto.randomBytes(16).toString('base64');

  const req = [
    `GET ${path} HTTP/1.1`,
    `Host: ${host}`,
    'Connection: Upgrade',
    'Upgrade: websocket',
    'Sec-WebSocket-Version: 13',
    `Sec-WebSocket-Key: ${wsKey}`,
    `Origin: ${origin}`,
    `Cookie: clawea_session=${encodeURIComponent(cookieToken)}`,
    'User-Agent: clawbureau-smoke-controlui-ws',
    '',
    '',
  ].join('\r\n');

  await writeAll(socket, Buffer.from(req, 'utf8'));

  const { head, rest } = await readUntil(socket, Buffer.from('\r\n\r\n'));
  const resp = parseHttpResponseHead(head);

  assert(resp.status === 101, `WS upgrade expected 101, got ${resp.status}: ${resp.raw}`);

  return { socket, rest };
}

async function smoke() {
  const args = parseArgs(process.argv.slice(2));
  const envName = String(args.get('env') || 'staging').toLowerCase();
  const agentId = String(args.get('agent') || '').trim();

  assert(agentId.length > 0, 'Missing --agent <agentId>');

  const tenantKey = process.env.CLAWEA_TENANT_KEY?.trim();
  assert(typeof tenantKey === 'string' && tenantKey.length > 0, 'Missing CLAWEA_TENANT_KEY env var');

  const baseUrlArg = args.get('base-url');

  const baseUrl =
    typeof baseUrlArg === 'string' && baseUrlArg.trim().length > 0
      ? String(baseUrlArg).trim()
      : envName === 'prod' || envName === 'production'
          ? 'https://clawea.com'
          : 'https://clawea.com/staging';

  const base = new URL(baseUrl);
  const origin = `${base.protocol}//${base.host}`;
  const host = base.host;
  const pathPrefix = base.pathname.replace(/\/$/, '');

  // 1) Mint control-session token
  const sessionRes = await httpJson(`${origin}${pathPrefix}/v1/agents/${encodeURIComponent(agentId)}/control-session`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${tenantKey}`,
    },
  });

  assert(sessionRes.status === 200, `control-session expected 200, got ${sessionRes.status}: ${sessionRes.text}`);
  assert(isRecord(sessionRes.json) && typeof sessionRes.json.url === 'string', 'control-session response missing url');

  const sessionUrl = new URL(String(sessionRes.json.url), origin);
  const sessionToken = sessionUrl.searchParams.get('session') || '';
  assert(sessionToken.trim().length > 0, 'control-session url missing ?session=...');

  // 2) Upgrade WS using cookie-only auth
  const wsPath = `${pathPrefix}/v1/agent/${encodeURIComponent(agentId)}/ws`;
  const { socket, rest } = await openWebSocket({
    host,
    path: wsPath,
    origin,
    cookieToken: sessionToken,
  });

  /** @type {Buffer} */
  let buf = rest;

  const connectFrame = {
    type: 'req',
    id: '1',
    method: 'connect',
    params: {
      // Required by the OpenClaw gateway protocol (PROTOCOL_VERSION currently 3)
      minProtocol: 3,
      maxProtocol: 3,
      client: {
        id: 'openclaw-control-ui',
        displayName: 'clawea-smoke',
        version: 'clawea-smoke',
        platform: 'web',
        mode: 'ui',
      },
      // Intentionally omit the gateway password. The clawea WS proxy should inject it.
      auth: {},
    },
  };

  // Send connect request
  await writeAll(socket, encodeClientTextFrame(JSON.stringify(connectFrame)));

  const deadline = Date.now() + 15_000;

  while (Date.now() < deadline) {
    const parsed = tryParseServerFrame(buf);
    if (parsed) {
      buf = parsed.rest;

      // Ping → pong
      if (parsed.opcode === 0x9) {
        await writeAll(socket, encodeClientControlFrame(0xA, parsed.payload));
        continue;
      }

      // Text frame
      if (parsed.opcode === 0x1) {
        const text = parsed.payload.toString('utf8');
        let msg;
        try {
          msg = JSON.parse(text);
        } catch {
          continue;
        }

        if (isRecord(msg) && msg.type === 'res' && msg.id === '1') {
          assert(msg.ok === true, `connect failed: ${text}`);

          // Close politely
          try {
            await writeAll(socket, encodeClientControlFrame(0x8));
          } catch {}
          try {
            socket.end();
          } catch {}

          console.log(
            JSON.stringify(
              {
                ok: true,
                env: envName,
                baseUrl,
                agentId,
                wsPath,
              },
              null,
              2,
            ),
          );

          return;
        }
      }

      // Close frame
      if (parsed.opcode === 0x8) break;

      continue;
    }

    // Need more data
    const chunk = await Promise.race([
      new Promise((resolve, reject) => {
        socket.once('data', resolve);
        socket.once('error', reject);
        socket.once('end', () => reject(new Error('socket_end')));
      }),
      new Promise((resolve) => setTimeout(() => resolve(null), 250)),
    ]);

    if (chunk) buf = Buffer.concat([buf, chunk]);
  }

  throw new Error('Timed out waiting for connect response');
}

smoke().catch((err) => {
  console.error(err);
  process.exit(1);
});
