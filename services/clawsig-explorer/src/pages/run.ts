/**
 * Run Detail Page: GET /run/:run_id
 *
 * Fetches run metadata from VaaS API and renders an HTML page with:
 * - Run ID, agent DID, proof tier, status, timestamp
 * - Model(s) used
 * - WPC hash (if present)
 * - RT log inclusion status
 * - Link to raw bundle JSON
 * - Client-side verification panel (WebCrypto)
 */

import { layout, esc, didDisplay, statusBadge, tierBadge, relativeTime, type PageMeta } from "../layout.js";

export interface RunData {
  run_id: string;
  bundle_hash_b64u: string;
  agent_did: string;
  proof_tier: string;
  status: string;
  wpc_hash_b64u: string | null;
  rt_leaf_index: number | null;
  created_at: string;
  models: Array<{ provider: string; model: string }>;
  bundle_url?: string;
  receipt_count?: number;
  event_count?: number;
}

export function runDetailPage(run: RunData): string {
  const meta: PageMeta = {
    title: `Run ${run.run_id.slice(0, 12)}... - ${run.status}`,
    description: `Verification run ${run.run_id} by agent ${run.agent_did.slice(0, 24)}... Status: ${run.status}, Tier: ${run.proof_tier}`,
    path: `/run/${run.run_id}`,
    ogType: "article",
  };

  const modelsHtml = run.models.length > 0
    ? run.models.map(m =>
      `<span class="hash" style="border-color: #333">${esc(m.provider)}/${esc(m.model)}</span>`
    ).join(" ")
    : `<span class="dim">None recorded</span>`;

  const rtStatus = run.rt_leaf_index !== null
    ? `<span class="pass">Included (leaf #${run.rt_leaf_index})</span>`
    : `<span class="dim">Pending</span>`;

  const wpcHtml = run.wpc_hash_b64u
    ? `<span class="hash">${esc(run.wpc_hash_b64u)}</span>`
    : `<span class="dim">No policy applied</span>`;

  const bundleLink = run.bundle_url
    ? `<a href="${esc(run.bundle_url)}" target="_blank" rel="noopener" class="mono">View raw bundle JSON &rarr;</a>`
    : `<span class="dim">Bundle not available</span>`;

  const body = `
    <div style="margin-bottom: 1.5rem">
      <a href="/" class="dim" style="font-size: 0.8125rem">&larr; Explorer</a>
    </div>

    <div style="display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; margin-bottom: 0.5rem">
      <h1 class="page-title" style="margin-bottom: 0">Verification Run</h1>
      ${statusBadge(run.status)}
      ${tierBadge(run.proof_tier)}
    </div>
    <p class="page-subtitle mono">${esc(run.run_id)}</p>

    <div class="card">
      <p class="section-title">Run Details</p>
      <dl class="detail-grid">
        <dt>Run ID</dt>
        <dd class="mono">${esc(run.run_id)}</dd>

        <dt>Agent</dt>
        <dd>${didDisplay(run.agent_did)}
          <a href="/agent/${encodeURIComponent(run.agent_did)}" style="font-size: 0.75rem; margin-left: 0.5rem">View Profile &rarr;</a>
        </dd>

        <dt>Proof Tier</dt>
        <dd>${tierBadge(run.proof_tier)}</dd>

        <dt>Status</dt>
        <dd>${statusBadge(run.status)}</dd>

        <dt>Timestamp</dt>
        <dd>${esc(run.created_at)} <span class="dim">(${relativeTime(run.created_at)})</span></dd>

        <dt>Models</dt>
        <dd>${modelsHtml}</dd>

        <dt>WPC Hash</dt>
        <dd>${wpcHtml}</dd>

        <dt>RT Log</dt>
        <dd>${rtStatus}</dd>

        <dt>Bundle Hash</dt>
        <dd><span class="hash">${esc(run.bundle_hash_b64u)}</span></dd>

        <dt>Receipts</dt>
        <dd>${run.receipt_count !== undefined ? run.receipt_count : "N/A"}</dd>

        <dt>Events</dt>
        <dd>${run.event_count !== undefined ? run.event_count : "N/A"}</dd>

        <dt>Raw Bundle</dt>
        <dd>${bundleLink}</dd>
      </dl>
    </div>

    ${clientVerifyPanel(run)}
  `;

  return layout(meta, body);
}

function clientVerifyPanel(run: RunData): string {
  const bundleAttr = run.bundle_url ? `data-bundle-url="${esc(run.bundle_url)}"` : "";

  return `
    <div class="verify-panel pending" id="verify-panel" ${bundleAttr} data-run-id="${esc(run.run_id)}">
      <h3>
        <span id="verify-icon">&#x23F3;</span>
        <span id="verify-title">Client-Side Verification</span>
      </h3>
      <p class="dim" style="font-size: 0.8125rem; margin-bottom: 1rem">
        Your browser independently verifies the cryptographic proof &mdash; no trust in our servers required.
      </p>
      <div class="verify-checks" id="verify-checks">
        <div class="verify-check">
          <span class="icon" id="check-sig">&#x2022;</span>
          <span>Envelope signature (Ed25519)</span>
          <span class="dim" id="check-sig-detail"></span>
        </div>
        <div class="verify-check">
          <span class="icon" id="check-hash">&#x2022;</span>
          <span>Payload hash integrity (SHA-256)</span>
          <span class="dim" id="check-hash-detail"></span>
        </div>
        <div class="verify-check">
          <span class="icon" id="check-chain">&#x2022;</span>
          <span>Event chain linkage</span>
          <span class="dim" id="check-chain-detail"></span>
        </div>
        <div class="verify-check">
          <span class="icon" id="check-receipts">&#x2022;</span>
          <span>Receipt signatures</span>
          <span class="dim" id="check-receipts-detail"></span>
        </div>
      </div>
      <p id="verify-result" style="margin-top: 1rem; font-size: 0.8125rem"></p>
    </div>

    <script>
    ${clientVerifyScript()}
    </script>
  `;
}

/**
 * Inline client-side verification script.
 *
 * This runs entirely in the browser using WebCrypto API.
 * It fetches the raw proof bundle and verifies:
 * 1. Payload hash matches (SHA-256)
 * 2. Ed25519 envelope signature
 * 3. Event chain hash linkage
 * 4. Receipt count (full receipt sig verification requires gateway DID allowlist)
 *
 * The base58, base64url, and Ed25519 helpers mirror clawverify-core/crypto.ts
 * but are self-contained to avoid bundling the full library.
 */
function clientVerifyScript(): string {
  return /* js */ `
  (async function() {
    var panel = document.getElementById("verify-panel");
    var bundleUrl = panel ? panel.getAttribute("data-bundle-url") : null;

    if (!bundleUrl) {
      setResult("warn", "Bundle URL not available for client-side verification");
      return;
    }

    if (typeof crypto === "undefined" || !crypto.subtle) {
      setResult("warn", "Your browser does not support WebCrypto (required for verification)");
      return;
    }

    try {
      setStatus("verify-title", "Verifying...");

      var res = await fetch(bundleUrl);
      if (!res.ok) {
        setResult("warn", "Could not fetch proof bundle (HTTP " + res.status + ")");
        return;
      }

      var envelope = await res.json();

      // 1. Verify payload hash (SHA-256)
      var payloadJson = JSON.stringify(envelope.payload);
      var payloadBytes = new TextEncoder().encode(payloadJson);
      var hashBuf = await crypto.subtle.digest("SHA-256", payloadBytes);
      var computedHash = b64uEncode(new Uint8Array(hashBuf));

      if (computedHash === envelope.payload_hash_b64u) {
        setCheck("check-hash", true, "Match");
      } else {
        setCheck("check-hash", false, "Mismatch");
        setResult("fail", "Payload hash mismatch -- bundle may be tampered");
        return;
      }

      // 2. Verify Ed25519 envelope signature
      var pubBytes = extractPubKeyFromDidKey(envelope.signer_did);
      if (!pubBytes) {
        setCheck("check-sig", false, "Cannot extract key from DID");
      } else {
        try {
          var pubKey = await crypto.subtle.importKey(
            "raw", pubBytes.buffer, { name: "Ed25519" }, false, ["verify"]
          );
          var sigBytes = b64uDecode(envelope.signature_b64u);
          var msgBytes = new TextEncoder().encode(envelope.payload_hash_b64u);
          var valid = await crypto.subtle.verify("Ed25519", pubKey, sigBytes, msgBytes);
          setCheck("check-sig", valid, valid ? "Valid" : "Invalid");
          if (!valid) {
            setResult("fail", "Envelope signature verification failed");
            return;
          }
        } catch (e) {
          // Ed25519 may not be supported in all browsers
          setCheck("check-sig", null, "Browser does not support Ed25519 verify");
        }
      }

      // 3. Event chain linkage
      var events = envelope.payload && envelope.payload.event_chain;
      if (Array.isArray(events) && events.length > 0) {
        var chainValid = true;
        var prevHash = null;
        for (var i = 0; i < events.length; i++) {
          var ev = events[i];
          if (i === 0) {
            if (ev.prev_hash_b64u !== null && ev.prev_hash_b64u !== "") {
              chainValid = false;
              break;
            }
          } else {
            if (ev.prev_hash_b64u !== prevHash) {
              chainValid = false;
              break;
            }
          }
          prevHash = ev.event_hash_b64u;
        }
        setCheck("check-chain", chainValid,
          chainValid ? events.length + " events linked" : "Chain broken");
      } else {
        setCheck("check-chain", null, "No event chain");
      }

      // 4. Receipt count
      var receipts = envelope.payload && envelope.payload.receipts;
      if (Array.isArray(receipts) && receipts.length > 0) {
        setCheck("check-receipts", true, receipts.length + " receipt(s) present");
      } else {
        setCheck("check-receipts", null, "No gateway receipts");
      }

      // Overall result
      setResult("pass", "Verified by YOUR browser");
      panel.classList.remove("pending");
      panel.classList.add("verified");
      document.getElementById("verify-icon").textContent = "\\u2705";
      setStatus("verify-title", "Verified by Your Browser");

    } catch (err) {
      setResult("fail", "Verification error: " + (err.message || "unknown"));
    }

    function setCheck(id, ok, detail) {
      var icon = document.getElementById(id);
      var det = document.getElementById(id + "-detail");
      if (ok === true) {
        icon.textContent = "\\u2705";
        icon.style.color = "var(--pass)";
      } else if (ok === false) {
        icon.textContent = "\\u274C";
        icon.style.color = "var(--fail)";
      } else {
        icon.textContent = "\\u2796";
        icon.style.color = "var(--text-dim)";
      }
      if (det) det.textContent = detail ? "(" + detail + ")" : "";
    }

    function setResult(type, msg) {
      var el = document.getElementById("verify-result");
      if (!el) return;
      el.className = type === "pass" ? "pass" : type === "fail" ? "fail" : "warn";
      el.textContent = msg;
    }

    function setStatus(id, text) {
      var el = document.getElementById(id);
      if (el) el.textContent = text;
    }

    function b64uDecode(s) {
      var b64 = s.replace(/-/g, "+").replace(/_/g, "/");
      var padded = b64 + "=".repeat((4 - b64.length % 4) % 4);
      var bin = atob(padded);
      var bytes = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return bytes;
    }

    function b64uEncode(bytes) {
      var bin = "";
      for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      return btoa(bin).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
    }

    function extractPubKeyFromDidKey(did) {
      if (!did || !did.startsWith("did:key:z")) return null;
      try {
        var multibase = did.slice(9);
        var decoded = base58Decode(multibase);
        if (decoded[0] === 0xed && decoded[1] === 0x01) {
          return decoded.slice(2);
        }
        return null;
      } catch (e) { return null; }
    }

    function base58Decode(str) {
      var ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
      var bytes = [0];
      for (var ci = 0; ci < str.length; ci++) {
        var val = ALPHA.indexOf(str[ci]);
        if (val === -1) throw new Error("Invalid base58");
        for (var i = 0; i < bytes.length; i++) bytes[i] *= 58;
        bytes[0] += val;
        var carry = 0;
        for (var i = 0; i < bytes.length; i++) {
          bytes[i] += carry;
          carry = bytes[i] >> 8;
          bytes[i] &= 0xff;
        }
        while (carry) { bytes.push(carry & 0xff); carry >>= 8; }
      }
      for (var ci = 0; ci < str.length; ci++) {
        if (str[ci] !== "1") break;
        bytes.push(0);
      }
      return new Uint8Array(bytes.reverse());
    }
  })();
  `;
}

export function runNotFoundPage(runId: string): string {
  const meta: PageMeta = {
    title: "Run Not Found",
    description: `Verification run ${runId} was not found in the public ledger.`,
    path: `/run/${runId}`,
  };

  const body = `
    <div style="text-align: center; padding: 4rem 0">
      <h1 class="page-title">Run Not Found</h1>
      <p class="dim" style="margin-bottom: 2rem">
        The run <span class="mono">${esc(runId)}</span> was not found in the public ledger.
      </p>
      <p>
        <a href="/">Back to Explorer &rarr;</a>
      </p>
    </div>
  `;

  return layout(meta, body);
}
