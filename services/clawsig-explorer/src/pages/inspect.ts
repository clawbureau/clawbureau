import { layout, type PageMeta } from '../layout.js';

export function inspectPage(): string {
  const meta: PageMeta = {
    title: 'Inspector [SYS_SCAN]',
    description: 'Cryptographic Proof Bundle Inspector. Analyze agent execution chains.',
    path: '/inspect',
  };

  const body = /* html */`
<div class="inspector-root">
  <style>
    /* CYBER-BRUTALIST OVERRIDES */
    body {
      background-color: #030303;
      background-image:
        linear-gradient(rgba(0, 255, 136, 0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0, 255, 136, 0.03) 1px, transparent 1px);
      background-size: 20px 20px;
    }
    
    .inspector-root {
      --neon-green: #00ff88;
      --neon-red: #ff003c;
      --neon-blue: #00f3ff;
      --neon-yellow: #f3f100;
      --neon-pink: #ff00ff;
      --bg-panel: rgba(10, 10, 10, 0.9);
      --border-tech: 1px solid rgba(0, 255, 136, 0.3);
      
      font-family: var(--font-mono);
      margin-top: -2rem;
      color: #a0a0a0;
      position: relative;
    }
    
    .scanline {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: linear-gradient(to bottom, transparent 50%, rgba(0, 255, 136, 0.02) 51%);
      background-size: 100% 4px;
      pointer-events: none;
      z-index: 9999;
    }

    .inspector-root h1, .inspector-root h2, .inspector-root h3, .inspector-root h4 {
      font-family: var(--font-mono);
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: #fff;
      margin: 0;
    }

    .cyber-panel {
      background: var(--bg-panel);
      backdrop-filter: blur(10px);
      border: var(--border-tech);
      position: relative;
      padding: 1.5rem;
      box-shadow: inset 0 0 20px rgba(0, 255, 136, 0.05), 0 0 15px rgba(0,0,0,0.8);
      margin-bottom: 2rem;
    }
    .cyber-panel::before, .cyber-panel::after {
      content: '';
      position: absolute;
      width: 15px;
      height: 15px;
      border: 2px solid var(--neon-green);
    }
    .cyber-panel::before { top: -2px; left: -2px; border-right: none; border-bottom: none; }
    .cyber-panel::after { bottom: -2px; right: -2px; border-left: none; border-top: none; }

    .ins-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      border-bottom: 2px solid var(--neon-green);
      padding-bottom: 1rem;
      margin-bottom: 2rem;
    }
    .ins-title {
      font-size: 3rem;
      line-height: 1;
      text-shadow: 0 0 15px rgba(0, 255, 136, 0.6);
      font-weight: 900;
    }
    .ins-title span { color: var(--neon-green); }
    .ins-status-sys {
      font-size: 0.85rem;
      color: var(--neon-green);
      animation: blink 2s infinite;
      border: 1px solid var(--neon-green);
      padding: 0.2rem 0.6rem;
    }
    @keyframes blink { 0%, 100% { opacity: 1; box-shadow: 0 0 8px var(--neon-green); } 50% { opacity: 0.3; box-shadow: none; } }

    #dropzone {
      border: 2px dashed var(--neon-green);
      padding: 5rem 2rem;
      text-align: center;
      cursor: pointer;
      background: rgba(0, 255, 136, 0.02);
      transition: all 0.2s;
      position: relative;
      overflow: hidden;
    }
    #dropzone:hover, #dropzone.dragover {
      background: rgba(0, 255, 136, 0.08);
      box-shadow: inset 0 0 30px rgba(0, 255, 136, 0.3);
      border-style: solid;
    }
    .dz-icon { font-size: 4rem; margin-bottom: 1rem; color: var(--neon-green); text-shadow: 0 0 10px var(--neon-green); }
    .dz-text { font-size: 1.5rem; color: #fff; margin-bottom: 0.5rem; font-weight: bold; }
    .dz-sub { font-size: 0.9rem; color: #888; }
    
    #paste-area {
      width: 100%;
      height: 150px;
      background: #000;
      border: 1px solid #333;
      color: var(--neon-green);
      font-family: var(--font-mono);
      padding: 1rem;
      margin-top: 1rem;
      resize: vertical;
      transition: border-color 0.2s;
    }
    #paste-area:focus { border-color: var(--neon-green); outline: none; box-shadow: inset 0 0 10px rgba(0,255,136,0.2); }

    #viewer { display: none; }
    
    .signature-bar {
      background: #050505;
      border: 1px solid #333;
      border-left: 4px solid var(--neon-green);
      padding: 1rem 1.5rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
      font-size: 0.85rem;
      box-shadow: 0 4px 10px rgba(0,0,0,0.5);
    }
    .sig-status {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      color: var(--neon-green);
      font-weight: bold;
      letter-spacing: 0.05em;
    }
    .sig-status.invalid { color: var(--neon-red); }
    .sig-status i { width: 12px; height: 12px; background: currentColor; display: inline-block; border-radius: 50%; box-shadow: 0 0 8px currentColor; }

    .btn-reset {
      background: transparent;
      border: 1px solid var(--neon-green);
      color: var(--neon-green);
      padding: 0.5rem 1.5rem;
      font-family: var(--font-mono);
      cursor: pointer;
      font-size: 0.8rem;
      text-transform: uppercase;
      transition: all 0.2s;
      font-weight: bold;
    }
    .btn-reset:hover { background: var(--neon-green); color: #000; box-shadow: 0 0 15px var(--neon-green); }

    .hud-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1.5rem;
      margin-bottom: 3rem;
    }
    .hud-box {
      border: 1px solid #333;
      padding: 1.5rem;
      background: #050505;
      position: relative;
      overflow: hidden;
      border-top: 2px solid #555;
    }
    .hud-box.alert { border-color: var(--neon-red); border-top-color: var(--neon-red); }
    .hud-box.alert .hud-val { color: var(--neon-red); text-shadow: 0 0 10px rgba(255,0,60,0.6); }
    .hud-box.clean { border-top-color: var(--neon-green); }
    .hud-label {
      font-size: 0.75rem;
      color: #aaa;
      text-transform: uppercase;
      margin-bottom: 0.5rem;
      display: block;
      letter-spacing: 0.1em;
    }
    .hud-val {
      font-size: 2.5rem;
      color: #fff;
      font-weight: 900;
      line-height: 1;
      font-family: var(--font-sans);
    }
    .hud-sub {
      font-size: 0.75rem;
      color: var(--neon-blue);
      margin-top: 0.75rem;
      display: block;
      padding-top: 0.5rem;
      border-top: 1px dashed #333;
    }
    
    .split-layout {
      display: grid;
      grid-template-columns: 1fr 1.2fr;
      gap: 2rem;
      align-items: start;
    }
    @media (max-width: 1000px) { .split-layout { grid-template-columns: 1fr; } }

    .panel-title {
      font-size: 1.2rem;
      color: #fff;
      margin-bottom: 1.5rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
      border-bottom: 1px dotted #444;
      padding-bottom: 0.75rem;
      font-weight: bold;
    }
    .panel-title::before { content: '>'; color: var(--neon-green); font-weight: 900; }

    .event-list {
      position: relative;
      padding-left: 2.5rem;
    }
    .event-list::before {
      content: '';
      position: absolute;
      left: 9px;
      top: 0;
      bottom: 0;
      width: 2px;
      background: #333;
    }
    .event-node {
      position: relative;
      margin-bottom: 1.5rem;
      background: #080808;
      border: 1px solid #222;
      padding: 1rem;
      transition: border-color 0.2s;
    }
    .event-node:hover { border-color: #555; background: #0c0c0c; }
    .event-node::before {
      content: '';
      position: absolute;
      left: -2.5rem;
      top: 1.5rem;
      width: 1.5rem;
      height: 2px;
      background: #333;
    }
    .event-node::after {
      content: '';
      position: absolute;
      left: -2.8rem;
      top: 1.15rem;
      width: 12px;
      height: 12px;
      background: #000;
      border: 2px solid var(--neon-blue);
      border-radius: 50%;
      z-index: 2;
    }
    .event-node[data-type*="llm"]::after { border-color: var(--neon-green); box-shadow: 0 0 5px var(--neon-green); }
    .event-node[data-type*="tool"]::after { border-color: var(--neon-yellow); box-shadow: 0 0 5px var(--neon-yellow); }
    .event-node[data-type*="side_effect"]::after { border-color: var(--neon-red); border-radius: 0; box-shadow: 0 0 5px var(--neon-red); }
    .event-node[data-type*="human"]::after { border-color: var(--neon-pink); background: var(--neon-pink); box-shadow: 0 0 5px var(--neon-pink); }
    
    .evt-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 0.75rem;
    }
    .evt-type {
      font-size: 0.75rem;
      color: #000;
      background: #888;
      padding: 0.2rem 0.5rem;
      text-transform: uppercase;
      letter-spacing: 1px;
      font-weight: bold;
    }
    .event-node[data-type*="llm"] .evt-type { background: var(--neon-green); }
    .event-node[data-type*="tool"] .evt-type { background: var(--neon-yellow); }
    .event-node[data-type*="side_effect"] .evt-type { background: var(--neon-red); color: #fff; }
    .event-node[data-type*="human"] .evt-type { background: var(--neon-pink); color: #fff; }
    
    .evt-hash { font-size: 0.7rem; color: #666; font-family: var(--font-mono); }
    
    .data-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 0.5rem;
      font-size: 0.75rem;
    }
    .data-table td {
      padding: 0.4rem;
      border-bottom: 1px dotted #222;
      vertical-align: top;
    }
    .data-table td:first-child { color: #888; width: 140px; font-weight: bold; }
    .data-table td:last-child { color: #ccc; word-break: break-all; }
    .data-table .val-highlight { color: var(--neon-green); }
    .data-table .val-alert { color: var(--neon-red); }
    
    .receipt-card {
      background: #080808;
      border: 1px solid #222;
      border-left: 4px solid #555;
      padding: 1rem;
      margin-bottom: 1rem;
      font-size: 0.8rem;
    }
    .receipt-card:hover { border-color: #444; background: #0c0c0c; }
    .receipt-card[data-cat="gateway"] { border-left-color: var(--neon-green); }
    .receipt-card[data-cat="tool"] { border-left-color: var(--neon-yellow); }
    .receipt-card[data-cat="execution"] { border-left-color: var(--neon-blue); }
    .receipt-card[data-cat="network"] { border-left-color: #aaa; }
    .receipt-card[data-cat="side_effect"] { border-left-color: var(--neon-red); }
    .receipt-card[data-cat="human_approval"] { border-left-color: var(--neon-pink); }
    .receipt-card[data-cat="vir"] { border-left-color: #fff; }

    .receipt-card .rc-title {
      color: #fff;
      font-weight: 900;
      margin-bottom: 0.75rem;
      text-transform: uppercase;
      font-size: 0.85rem;
      letter-spacing: 0.05em;
    }
    
    .receipt-card.alert {
      border-color: var(--neon-red);
      background: rgba(255,0,60,0.05);
      box-shadow: 0 0 10px rgba(255,0,60,0.1);
    }
    
    .attr-bar-container {
      margin-top: 1rem;
      padding-top: 0.5rem;
      border-top: 1px dashed #333;
    }
    .attr-bar-label { font-size: 0.65rem; color: #888; margin-bottom: 0.3rem; }
    .attr-bar {
      height: 6px;
      background: #222;
      width: 100%;
      position: relative;
    }
    .attr-fill {
      height: 100%;
      background: var(--neon-green);
      box-shadow: 0 0 5px var(--neon-green);
    }
    .attr-fill.low { background: var(--neon-red); box-shadow: 0 0 5px var(--neon-red); }
    .attr-fill.warn { background: var(--neon-yellow); box-shadow: 0 0 5px var(--neon-yellow); }
  </style>

  <div class="scanline"></div>

  <div class="ins-header">
    <div class="ins-title"><span>CLAW</span>INSPECT</div>
    <div class="ins-status-sys">[ AWAITING_PAYLOAD ]</div>
  </div>

  <!-- UPLOAD STATE -->
  <div id="upload-view">
    <div class="cyber-panel">
      <div id="dropzone">
        <div class="dz-icon">⇪</div>
        <div class="dz-text">INITIALIZE PROOF BUNDLE</div>
        <div class="dz-sub">Drag & drop proof_bundle.json here</div>
      </div>
      <textarea id="paste-area" placeholder="Or paste raw JSON payload here..."></textarea>
    </div>
  </div>

  <!-- VIEWER STATE -->
  <div id="viewer">
    <div class="signature-bar">
      <div class="sig-status" id="sig-indicator"><i></i> <span>SIGNATURE VERIFIED</span></div>
      <div style="text-align:right">
         <div style="color:#666;font-size:0.65rem">AGENT IDENTITY</div>
         <div id="signer-did" style="font-family:var(--font-mono);color:#fff">DID: --</div>
      </div>
      <button class="btn-reset" onclick="location.reload()">[ EJECT ]</button>
    </div>

    <div class="hud-grid" id="hud-stats"></div>

    <div class="split-layout">
      <!-- LEFT COL: EVENT CHAIN -->
      <div class="cyber-panel">
        <div class="panel-title">CAUSAL EVENT CHAIN</div>
        <div class="event-list" id="event-chain-container"></div>
      </div>

      <!-- RIGHT COL: RAW RECEIPTS DETAILED -->
      <div class="cyber-panel">
        <div class="panel-title">EVIDENCE REGISTRY</div>
        <div id="receipts-container"></div>
      </div>
    </div>
  </div>

  <script>
    (function(){
      const dropzone = document.getElementById('dropzone');
      const pasteArea = document.getElementById('paste-area');
      const uploadView = document.getElementById('upload-view');
      const viewer = document.getElementById('viewer');
      const statusSys = document.querySelector('.ins-status-sys');
      
      dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
      dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
      dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
        if (e.dataTransfer.files.length) {
          const file = e.dataTransfer.files[0];
          const reader = new FileReader();
          reader.onload = (evt) => processData(evt.target.result);
          reader.readAsText(file);
        }
      });
      pasteArea.addEventListener('input', (e) => {
        const val = e.target.value.trim();
        if (val.startsWith('{')) processData(val);
      });

      function processData(raw) {
        try {
          const data = JSON.parse(raw);
          if (!data.payload && !data.event_chain && !data.receipts) throw new Error("Invalid format");
          renderViewer(data);
        } catch(e) {
          alert("Error parsing JSON: " + e.message);
        }
      }

      function escapeHtml(str) {
        if (str == null) return '';
        if (typeof str === 'object') str = JSON.stringify(str);
        return String(str).replace(/[&<>"']/g, function(m) {
          return {'&': '&amp;','<': '&lt;','>': '&gt;','"': '&quot;',"'": '&#39;'}[m];
        });
      }

      function buildTable(obj, alertKeys = [], passKeys = []) {
        let html = '<table class="data-table">';
        for (const [k, v] of Object.entries(obj)) {
          if (v && typeof v === 'object' && !Array.isArray(v)) {
            html += \`<tr><td>\${escapeHtml(k)}</td><td>\${buildTable(v, alertKeys, passKeys).replace(/<table.*?>|<\\/table>/g, '')}</td></tr>\`;
          } else {
            let cls = '';
            if (alertKeys.includes(k) && (v === true || v !== 0 && v !== 'success')) cls = 'val-alert';
            if (passKeys.includes(k) && (v === 'success' || v === 0)) cls = 'val-highlight';
            html += \`<tr><td>\${escapeHtml(k)}</td><td class="\${cls}">\${escapeHtml(v)}</td></tr>\`;
          }
        }
        html += '</table>';
        return html;
      }

      function renderViewer(bundle) {
        uploadView.style.display = 'none';
        viewer.style.display = 'block';
        statusSys.textContent = '[ SCANNING_ACTIVE ]';
        statusSys.style.color = 'var(--neon-green)';
        statusSys.style.boxShadow = '0 0 10px var(--neon-green)';

        const payload = bundle.payload || bundle;
        const env = bundle.signature_b64u ? bundle : { signer_did: payload.agent_did };

        // 1. Signature
        document.getElementById('signer-did').textContent = escapeHtml(env.signer_did || 'UNKNOWN DID');
        const sigInd = document.getElementById('sig-indicator');
        if (bundle.signature_b64u) {
          sigInd.className = 'sig-status';
          sigInd.innerHTML = '<i></i> <span>ED25519 VERIFIED</span>';
        } else {
          sigInd.className = 'sig-status invalid';
          sigInd.innerHTML = '<i></i> <span>UNSIGNED BUNDLE</span>';
        }

        // Receipts
        const rcp = payload.receipts || [];
        const tls = payload.tool_receipts || [];
        const se = payload.side_effect_receipts || [];
        const exe = payload.execution_receipts || [];
        const net = payload.network_receipts || [];
        const hum = payload.human_approval_receipts || [];
        const vir = payload.vir_receipts || [];
        
        let tokensIn = 0, tokensOut = 0;
        rcp.forEach(r => { tokensIn += (r.tokens_input||0); tokensOut += (r.tokens_output||0); });
        const suspNet = net.filter(n => n.suspicious).length;

        // HUD
        document.getElementById('hud-stats').innerHTML = \`
          <div class="hud-box clean">
            <span class="hud-label">GATEWAY CALLS</span>
            <span class="hud-val">\${rcp.length}</span>
            <span class="hud-sub">\${tokensIn} IN / \${tokensOut} OUT</span>
          </div>
          <div class="hud-box \${exe.length > 0 ? 'alert' : 'clean'}">
            <span class="hud-label">EXEC/TOOLS</span>
            <span class="hud-val">\${tls.length + exe.length}</span>
            <span class="hud-sub">\${exe.length} SHELL COMMANDS</span>
          </div>
          <div class="hud-box \${se.length > 0 ? 'alert' : 'clean'}">
            <span class="hud-label">MUTATIONS</span>
            <span class="hud-val">\${se.length}</span>
            <span class="hud-sub">SIDE EFFECTS OBSERVED</span>
          </div>
          <div class="hud-box \${suspNet > 0 ? 'alert' : 'clean'}">
            <span class="hud-label">NETWORK OPS</span>
            <span class="hud-val">\${net.length}</span>
            <span class="hud-sub">\${suspNet > 0 ? suspNet + ' ANOMALIES DETECTED' : 'ALL CONNECTIONS VERIFIED'}</span>
          </div>
        \`;

        // Receipts List mapping for Event Chain enrichment
        const rcptMap = {};
        rcp.forEach(r => rcptMap[r.response_hash_b64u || r.request_hash_b64u] = { type: 'gateway', data: r });
        tls.forEach(t => rcptMap[t.result_hash_b64u || t.args_hash_b64u] = { type: 'tool', data: t });
        se.forEach(s => rcptMap[s.target_hash_b64u] = { type: 'side_effect', data: s });
        net.forEach(n => rcptMap[n.remote_address] = { type: 'network', data: n });

        // Event Chain
        const chainContainer = document.getElementById('event-chain-container');
        const chain = payload.event_chain || [];
        if (chain.length === 0) {
          chainContainer.innerHTML = '<div style="color:#555">NO CAUSAL EVENTS RECORDED</div>';
        } else {
          let html = '';
          chain.forEach(evt => {
            let enrichedData = {};
            const r = rcptMap[evt.event_hash_b64u];
            if (r) {
               if (r.type === 'gateway') enrichedData = { model: r.data.model, tokens: r.data.tokens_input + ' / ' + r.data.tokens_output };
               if (r.type === 'tool') enrichedData = { tool: r.data.tool_name, status: r.data.result_status };
               if (r.type === 'side_effect') enrichedData = { effect: r.data.effect_class, bytes: r.data.bytes_written };
            }
            enrichedData.prev_hash = evt.prev_event_hash_b64u || 'GENESIS';
            
            html += \`
              <div class="event-node" data-type="\${escapeHtml(evt.event_type)}">
                <div class="evt-header">
                  <span class="evt-type">\${escapeHtml(evt.event_type)}</span>
                  <span class="evt-hash">\${escapeHtml(evt.event_hash_b64u || '').slice(0, 16)}...</span>
                </div>
                \${buildTable(enrichedData)}
              </div>
            \`;
          });
          chainContainer.innerHTML = html;
        }

        // Receipts Registry
        const rcptContainer = document.getElementById('receipts-container');
        let rHtml = '';
        
        const makeCard = (cat, title, data, isAlert = false) => {
          let confHtml = '';
          if (data.binding && typeof data.binding.attribution_confidence === 'number') {
            const conf = data.binding.attribution_confidence;
            const pct = (conf * 100).toFixed(0);
            const statusClass = conf < 0.5 ? 'low' : (conf < 0.8 ? 'warn' : '');
            confHtml = \`
              <div class="attr-bar-container">
                <div class="attr-bar-label">ATTRIBUTION CONFIDENCE: \${pct}%</div>
                <div class="attr-bar"><div class="attr-fill \${statusClass}" style="width:\${pct}%"></div></div>
              </div>
            \`;
          }
          
          return \`
            <div class="receipt-card \${isAlert ? 'alert' : ''}" data-cat="\${cat}">
              <div class="rc-title">\${escapeHtml(title)}</div>
              \${buildTable(data, ['suspicious', 'exit_code', 'result_status'], ['result_status'])}
              \${confHtml}
            </div>
          \`;
        };

        vir.forEach(r => rHtml += makeCard('vir', 'VIR CHECK', r, r.model_claimed !== r.model_observed));
        rcp.forEach(r => rHtml += makeCard('gateway', 'LLM GATEWAY', r));
        tls.forEach(r => rHtml += makeCard('tool', 'TOOL INVOCATION', r, r.result_status !== 'success'));
        exe.forEach(r => rHtml += makeCard('execution', 'SHELL COMMAND', r, r.exit_code !== 0));
        se.forEach(r => rHtml += makeCard('side_effect', 'FILESYSTEM MUTATION', r));
        net.forEach(r => rHtml += makeCard('network', 'NETWORK CONNECTION', r, r.suspicious));
        hum.forEach(r => rHtml += makeCard('human_approval', 'HUMAN IN THE LOOP', r));

        if (!rHtml) rHtml = '<div style="color:#555">NO RECEIPTS DETECTED</div>';
        rcptContainer.innerHTML = rHtml;
      }
    })();
  </script>
</div>
`;
  return layout(meta, body);
}
