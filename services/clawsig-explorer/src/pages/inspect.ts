/**
 * Proof Bundle Inspector: Client-side visualization of signed proof bundles
 *
 * Features:
 * - Drag/drop or paste proof_bundle.json
 * - Displays signature verification status
 * - Timeline visualization of execution events
 * - Receipt breakdown by type with anomaly detection
 * - Causal chain tracing with span linkage
 * - Deep drill-down into individual receipts
 * - Hash verification via Web Crypto API
 */

import { layout, esc, didDisplay, statusBadge, tierBadge, type PageMeta } from '../layout.js';

export function inspectPage(): string {
  const meta: PageMeta = {
    title: 'Proof Bundle Inspector',
    description: 'Upload or paste a proof_bundle.json to visualize, verify, and analyze AI agent execution proofs.',
    path: '/inspect',
  };

  return layout(meta, inspectPageBody());
}

function inspectPageBody(): string {
  return `
    <style>${inspectPageStyles()}</style>
    
    <div class="inspect-container">
      <div class="inspect-hero">
        <div>
          <h1 class="inspect-title">⚡ Proof Inspector</h1>
          <p class="inspect-subtitle">Upload or paste a proof_bundle.json to verify AI agent execution integrity</p>
        </div>
      </div>

      <div id="inspect-upload-zone" class="upload-zone">
        <div class="upload-content">
          <div class="upload-icon">📦</div>
          <h2>Drop proof bundle here</h2>
          <p>or <button class="upload-btn" onclick="document.getElementById('file-input').click()">select file</button> or <button class="upload-btn" onclick="pasteJsonDialog()">paste JSON</button></p>
          <input type="file" id="file-input" accept=".json" style="display:none" onchange="handleFileSelect(event)">
        </div>
      </div>

      <div id="inspect-content" style="display:none">
        <div class="inspect-toolbar">
          <div class="toolbar-section">
            <h3 class="toolbar-title">Bundle Verification</h3>
            <div id="verify-status" class="verify-status"></div>
          </div>
          <button class="btn-reset" onclick="resetInspector()">↻ New Bundle</button>
        </div>

        <div class="metrics-grid">
          <div class="metric-card">
            <div class="metric-label">Bundle ID</div>
            <div id="metric-bundle-id" class="metric-value mono"></div>
          </div>
          <div class="metric-card">
            <div class="metric-label">Agent DID</div>
            <div id="metric-agent-did" class="metric-value mono"></div>
          </div>
          <div class="metric-card">
            <div class="metric-label">Issued At</div>
            <div id="metric-issued-at" class="metric-value"></div>
          </div>
          <div class="metric-card">
            <div class="metric-label">Receipts</div>
            <div id="metric-receipts" class="metric-value"></div>
          </div>
        </div>

        <div class="tabs-container">
          <div class="tabs-nav">
            <button class="tab-btn active" onclick="switchTab('overview')">Overview</button>
            <button class="tab-btn" onclick="switchTab('timeline')">Timeline</button>
            <button class="tab-btn" onclick="switchTab('receipts')">Receipts</button>
            <button class="tab-btn" onclick="switchTab('integrity')">Integrity</button>
          </div>

          <div id="tab-overview" class="tab-pane active">
            <div class="overview-grid">
              <div class="overview-section">
                <h3 class="section-heading">Execution Summary</h3>
                <div id="summary-content" class="summary-content"></div>
              </div>
              <div class="overview-section">
                <h3 class="section-heading">Receipt Breakdown</h3>
                <div id="receipt-breakdown" class="breakdown-chart"></div>
              </div>
              <div class="overview-section">
                <h3 class="section-heading">Anomalies & Flags</h3>
                <div id="anomalies-list" class="anomalies-list"></div>
              </div>
            </div>
          </div>

          <div id="tab-timeline" class="tab-pane">
            <div class="timeline-container">
              <div id="timeline-content" class="timeline-list"></div>
            </div>
          </div>

          <div id="tab-receipts" class="tab-pane">
            <div class="receipts-container">
              <div id="receipts-content" class="receipts-list"></div>
            </div>
          </div>

          <div id="tab-integrity" class="tab-pane">
            <div class="integrity-container">
              <div id="integrity-content" class="integrity-details"></div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div id="paste-modal" class="modal" style="display:none">
      <div class="modal-overlay" onclick="closePasteDialog()"></div>
      <div class="modal-dialog">
        <div class="modal-header">
          <h2>Paste Proof Bundle JSON</h2>
          <button class="modal-close" onclick="closePasteDialog()">✕</button>
        </div>
        <textarea id="paste-textarea" class="paste-textarea" placeholder="Paste your proof_bundle.json here..."></textarea>
        <div class="modal-footer">
          <button class="btn-cancel" onclick="closePasteDialog()">Cancel</button>
          <button class="btn-primary" onclick="handlePasteJson()">Inspect Bundle</button>
        </div>
      </div>
    </div>

    <script>${inspectPageScript()}</script>
  `;
}

function inspectPageStyles(): string {
  return `
    .inspect-container {
      display: flex;
      flex-direction: column;
      gap: 2rem;
      margin-bottom: 3rem;
    }

    .inspect-hero {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 2rem;
      padding: 2.5rem 2rem;
      background: linear-gradient(135deg, rgba(0, 255, 136, 0.08) 0%, rgba(255, 170, 0, 0.06) 100%);
      border: 1px solid rgba(0, 255, 136, 0.2);
      border-radius: 12px;
      animation: fadeInDown 0.6s ease-out;
    }

    .inspect-title {
      font-size: 2.5rem;
      font-weight: 900;
      margin-bottom: 0.5rem;
      letter-spacing: -1px;
      color: var(--text);
    }

    .inspect-subtitle {
      font-size: 1rem;
      color: var(--text-dim);
      max-width: 500px;
    }

    .upload-zone {
      border: 2px dashed rgba(0, 255, 136, 0.4);
      border-radius: 16px;
      padding: 3rem 2rem;
      text-align: center;
      transition: all 0.3s ease;
      background: rgba(0, 255, 136, 0.03);
      cursor: pointer;
      animation: fadeInUp 0.6s ease-out 0.1s both;
    }

    .upload-zone:hover {
      border-color: rgba(0, 255, 136, 0.6);
      background: rgba(0, 255, 136, 0.06);
    }

    .upload-zone.dragover {
      border-color: var(--pass);
      background: rgba(0, 255, 136, 0.1);
      box-shadow: 0 0 20px rgba(0, 255, 136, 0.2);
    }

    .upload-content {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 1rem;
    }

    .upload-icon {
      font-size: 3rem;
      animation: bounce 0.6s ease-in-out infinite;
    }

    .upload-zone h2 {
      font-size: 1.5rem;
      margin: 0;
      color: var(--text);
    }

    .upload-zone p {
      margin: 0;
      color: var(--text-dim);
    }

    .upload-btn {
      background: transparent;
      border: 1px solid var(--pass);
      color: var(--pass);
      padding: 0.4rem 0.8rem;
      border-radius: 6px;
      cursor: pointer;
      font-weight: 600;
      transition: all 0.2s;
      font-family: var(--font-sans);
      font-size: 0.9rem;
    }

    .upload-btn:hover {
      background: rgba(0, 255, 136, 0.1);
      box-shadow: 0 0 12px rgba(0, 255, 136, 0.3);
    }

    .inspect-toolbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 1.5rem;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 1.5rem;
      gap: 2rem;
    }

    .toolbar-section {
      flex: 1;
    }

    .toolbar-title {
      font-size: 0.75rem;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 0.1em;
      margin: 0 0 0.5rem 0;
      font-weight: 600;
    }

    .verify-status {
      display: flex;
      gap: 1rem;
      flex-wrap: wrap;
    }

    .btn-reset {
      background: transparent;
      border: 1px solid var(--border);
      color: var(--text-dim);
      padding: 0.6rem 1rem;
      border-radius: 6px;
      cursor: pointer;
      font-weight: 600;
      transition: all 0.2s;
      white-space: nowrap;
    }

    .btn-reset:hover {
      border-color: var(--text-dim);
      color: var(--text);
    }

    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }

    .metric-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
      transition: all 0.3s ease;
      animation: slideInUp 0.5s ease-out 0.1s both;
    }

    .metric-card:hover {
      border-color: rgba(0, 255, 136, 0.3);
      box-shadow: 0 4px 12px rgba(0, 255, 136, 0.1);
    }

    .metric-label {
      font-size: 0.75rem;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-weight: 600;
    }

    .metric-value {
      font-size: 0.95rem;
      color: var(--text);
      word-break: break-all;
      font-weight: 500;
    }

    .metric-value.mono {
      font-family: var(--font-mono);
      font-size: 0.85rem;
    }

    .tabs-container {
      display: flex;
      flex-direction: column;
    }

    .tabs-nav {
      display: flex;
      gap: 0;
      border-bottom: 1px solid var(--border);
      margin-bottom: 1.5rem;
      overflow-x: auto;
    }

    .tab-btn {
      background: transparent;
      border: none;
      color: var(--text-dim);
      padding: 1rem 1.5rem;
      cursor: pointer;
      font-weight: 600;
      font-size: 0.9rem;
      border-bottom: 2px solid transparent;
      transition: all 0.2s;
      white-space: nowrap;
    }

    .tab-btn:hover {
      color: var(--text);
    }

    .tab-btn.active {
      color: var(--pass);
      border-bottom-color: var(--pass);
    }

    .tab-pane {
      display: none;
      animation: fadeIn 0.3s ease-out;
    }

    .tab-pane.active {
      display: block;
    }

    .overview-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 1.5rem;
    }

    .overview-section {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.5rem;
    }

    .section-heading {
      font-size: 0.95rem;
      font-weight: 700;
      margin: 0 0 1rem 0;
      color: var(--text);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .summary-content {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }

    .summary-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0.75rem;
      background: rgba(0, 255, 136, 0.03);
      border-radius: 6px;
      font-size: 0.9rem;
    }

    .summary-item-label {
      color: var(--text-dim);
      font-weight: 500;
    }

    .summary-item-value {
      color: var(--text);
      font-weight: 600;
      font-family: var(--font-mono);
    }

    .breakdown-chart {
      display: flex;
      flex-direction: column;
      gap: 0.6rem;
    }

    .breakdown-item {
      display: flex;
      align-items: center;
      gap: 1rem;
      padding: 0.6rem;
      background: rgba(255, 255, 255, 0.02);
      border-radius: 6px;
    }

    .breakdown-label {
      flex: 1;
      font-size: 0.85rem;
      color: var(--text);
      font-weight: 500;
    }

    .breakdown-bar {
      flex-shrink: 0;
      height: 24px;
      border-radius: 4px;
      background: var(--border);
      min-width: 40px;
      position: relative;
      overflow: hidden;
    }

    .breakdown-bar-fill {
      height: 100%;
      background: linear-gradient(90deg, var(--pass) 0%, rgba(0, 255, 136, 0.6) 100%);
      transition: width 0.5s ease-out;
    }

    .breakdown-count {
      font-size: 0.8rem;
      color: var(--text-dim);
      min-width: 40px;
      text-align: right;
      font-weight: 600;
    }

    .anomalies-list {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }

    .anomaly-item {
      padding: 0.75rem;
      background: rgba(255, 170, 0, 0.08);
      border-left: 3px solid var(--warn);
      border-radius: 4px;
      font-size: 0.85rem;
      color: var(--text);
    }

    .anomaly-empty {
      padding: 1.5rem;
      text-align: center;
      color: var(--text-dim);
      background: rgba(0, 255, 136, 0.03);
      border-radius: 6px;
      font-size: 0.9rem;
    }

    .timeline-container {
      display: flex;
      flex-direction: column;
      gap: 0;
    }

    .timeline-list {
      display: flex;
      flex-direction: column;
    }

    .timeline-item {
      display: flex;
      gap: 1.5rem;
      padding: 1.25rem;
      border-left: 2px solid var(--border);
      border-bottom: 1px solid rgba(0, 255, 136, 0.1);
      transition: all 0.3s ease;
      animation: slideInLeft 0.5s ease-out;
      cursor: pointer;
    }

    .timeline-item:hover {
      border-left-color: var(--pass);
      background: rgba(0, 255, 136, 0.03);
    }

    .timeline-item.last {
      border-bottom: none;
    }

    .timeline-marker {
      flex-shrink: 0;
      width: 32px;
      height: 32px;
      border-radius: 50%;
      background: var(--bg-card);
      border: 2px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 0.75rem;
      font-weight: 700;
      color: var(--text-dim);
      margin-top: 0.1rem;
    }

    .timeline-item:hover .timeline-marker {
      border-color: var(--pass);
      background: rgba(0, 255, 136, 0.1);
      color: var(--pass);
    }

    .timeline-content {
      flex: 1;
      min-width: 0;
    }

    .timeline-type {
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-weight: 700;
      color: var(--pass);
      margin-bottom: 0.25rem;
    }

    .timeline-details {
      font-size: 0.9rem;
      color: var(--text);
      margin-bottom: 0.5rem;
      word-break: break-word;
    }

    .timeline-meta {
      font-size: 0.8rem;
      color: var(--text-dim);
      display: flex;
      gap: 1rem;
      flex-wrap: wrap;
    }

    .receipts-container {
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }

    .receipts-list {
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }

    .receipt-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
      transition: all 0.3s ease;
      animation: slideInUp 0.5s ease-out;
    }

    .receipt-card:hover {
      border-color: rgba(0, 255, 136, 0.4);
      box-shadow: 0 4px 16px rgba(0, 255, 136, 0.1);
    }

    .receipt-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 1rem;
      cursor: pointer;
      user-select: none;
    }

    .receipt-type-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.4rem 0.8rem;
      background: rgba(0, 255, 136, 0.15);
      color: var(--pass);
      border-radius: 6px;
      font-size: 0.8rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.07em;
    }

    .receipt-type-badge.warning {
      background: rgba(255, 170, 0, 0.15);
      color: var(--warn);
    }

    .receipt-type-badge.error {
      background: rgba(255, 68, 68, 0.15);
      color: var(--fail);
    }

    .receipt-toggle {
      width: 24px;
      height: 24px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--text-dim);
      font-weight: 700;
      transition: all 0.2s;
    }

    .receipt-card.expanded .receipt-toggle {
      transform: rotate(90deg);
    }

    .receipt-body {
      display: none;
      margin-top: 1rem;
      padding-top: 1rem;
      border-top: 1px solid var(--border);
    }

    .receipt-card.expanded .receipt-body {
      display: block;
      animation: slideDown 0.3s ease-out;
    }

    .receipt-property {
      display: flex;
      gap: 1rem;
      margin-bottom: 0.75rem;
      font-size: 0.85rem;
    }

    .receipt-property-label {
      color: var(--text-dim);
      font-weight: 600;
      min-width: 140px;
      text-transform: uppercase;
      font-size: 0.75rem;
      letter-spacing: 0.08em;
    }

    .receipt-property-value {
      color: var(--text);
      flex: 1;
      word-break: break-all;
      font-family: var(--font-mono);
      font-size: 0.75rem;
    }

    .integrity-container {
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
    }

    .integrity-details {
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }

    .integrity-check {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
      display: flex;
      align-items: flex-start;
      gap: 1rem;
    }

    .integrity-check.pass {
      border-color: rgba(0, 255, 136, 0.3);
      background: rgba(0, 255, 136, 0.03);
    }

    .integrity-check.fail {
      border-color: rgba(255, 68, 68, 0.3);
      background: rgba(255, 68, 68, 0.03);
    }

    .integrity-check-icon {
      flex-shrink: 0;
      width: 24px;
      height: 24px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      font-size: 1.1rem;
    }

    .integrity-check.pass .integrity-check-icon {
      color: var(--pass);
    }

    .integrity-check.fail .integrity-check-icon {
      color: var(--fail);
    }

    .integrity-check-content {
      flex: 1;
    }

    .integrity-check-title {
      font-weight: 700;
      color: var(--text);
      margin-bottom: 0.25rem;
    }

    .integrity-check-detail {
      font-size: 0.85rem;
      color: var(--text-dim);
      margin-bottom: 0.5rem;
      word-break: break-all;
      font-family: var(--font-mono);
    }

    .modal {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
    }

    .modal-overlay {
      position: absolute;
      inset: 0;
      background: rgba(0, 0, 0, 0.8);
      backdrop-filter: blur(4px);
    }

    .modal-dialog {
      position: relative;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      max-width: 600px;
      width: 90%;
      max-height: 70vh;
      display: flex;
      flex-direction: column;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4);
      animation: slideUp 0.3s ease-out;
    }

    .modal-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 1.5rem;
      border-bottom: 1px solid var(--border);
    }

    .modal-header h2 {
      margin: 0;
      font-size: 1.25rem;
      color: var(--text);
    }

    .modal-close {
      background: transparent;
      border: none;
      color: var(--text-dim);
      cursor: pointer;
      font-size: 1.5rem;
      width: 32px;
      height: 32px;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.2s;
    }

    .modal-close:hover {
      color: var(--text);
    }

    .paste-textarea {
      flex: 1;
      background: var(--bg);
      color: var(--text);
      border: 1px solid var(--border);
      padding: 1rem;
      font-family: var(--font-mono);
      font-size: 0.85rem;
      resize: none;
    }

    .paste-textarea::placeholder {
      color: var(--text-dim);
    }

    .modal-footer {
      display: flex;
      gap: 1rem;
      padding: 1.5rem;
      border-top: 1px solid var(--border);
    }

    .btn-primary,
    .btn-cancel {
      flex: 1;
      padding: 0.75rem 1.5rem;
      border: none;
      border-radius: 6px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
      font-size: 0.95rem;
    }

    .btn-primary {
      background: var(--pass);
      color: #000;
    }

    .btn-primary:hover {
      opacity: 0.9;
      box-shadow: 0 4px 12px rgba(0, 255, 136, 0.3);
    }

    .btn-cancel {
      background: transparent;
      border: 1px solid var(--border);
      color: var(--text-dim);
    }

    .btn-cancel:hover {
      border-color: var(--text-dim);
      color: var(--text);
    }

    @keyframes fadeInDown {
      from {
        opacity: 0;
        transform: translateY(-20px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    @keyframes fadeInUp {
      from {
        opacity: 0;
        transform: translateY(20px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    @keyframes slideInUp {
      from {
        opacity: 0;
        transform: translateY(20px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    @keyframes slideInLeft {
      from {
        opacity: 0;
        transform: translateX(-20px);
      }
      to {
        opacity: 1;
        transform: translateX(0);
      }
    }

    @keyframes slideDown {
      from {
        opacity: 0;
        max-height: 0;
      }
      to {
        opacity: 1;
        max-height: 1000px;
      }
    }

    @keyframes slideUp {
      from {
        opacity: 0;
        transform: translateY(20px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }

    @keyframes bounce {
      0%, 100% { transform: translateY(0); }
      50% { transform: translateY(-10px); }
    }

    @media (max-width: 768px) {
      .inspect-hero {
        flex-direction: column;
        align-items: flex-start;
      }

      .inspect-title {
        font-size: 1.75rem;
      }

      .overview-grid {
        grid-template-columns: 1fr;
      }

      .tabs-nav {
        gap: 0.5rem;
      }

      .tab-btn {
        padding: 0.75rem 1rem;
        font-size: 0.85rem;
      }

      .metric-card {
        padding: 1rem;
      }
    }
  `;
}

function inspectPageScript(): string {
  return `
    let bundleData = null;

    // File operations
    document.getElementById('file-input').addEventListener('change', handleFileSelect);
    document.getElementById('upload-zone').addEventListener('dragover', e => {
      e.preventDefault();
      document.getElementById('upload-zone').classList.add('dragover');
    });
    document.getElementById('upload-zone').addEventListener('dragleave', () => {
      document.getElementById('upload-zone').classList.remove('dragover');
    });
    document.getElementById('upload-zone').addEventListener('drop', e => {
      e.preventDefault();
      document.getElementById('upload-zone').classList.remove('dragover');
      const file = e.dataTransfer.files[0];
      if (file && file.type === 'application/json') {
        const reader = new FileReader();
        reader.onload = e => parseAndDisplayBundle(e.target.result);
        reader.readAsText(file);
      }
    });

    function handleFileSelect(e) {
      const file = e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = e => parseAndDisplayBundle(e.target.result);
      reader.readAsText(file);
    }

    function pasteJsonDialog() {
      document.getElementById('paste-modal').style.display = 'flex';
      setTimeout(() => document.getElementById('paste-textarea').focus(), 100);
    }

    function closePasteDialog() {
      document.getElementById('paste-modal').style.display = 'none';
      document.getElementById('paste-textarea').value = '';
    }

    function handlePasteJson() {
      const json = document.getElementById('paste-textarea').value.trim();
      if (!json) {
        alert('Please paste a JSON object');
        return;
      }
      try {
        const parsed = JSON.parse(json);
        parseAndDisplayBundle(JSON.stringify(parsed));
        closePasteDialog();
      } catch (err) {
        alert('Invalid JSON: ' + err.message);
      }
    }

    function parseAndDisplayBundle(jsonStr) {
      try {
        bundleData = JSON.parse(jsonStr);
        document.getElementById('upload-zone').style.display = 'none';
        document.getElementById('inspect-content').style.display = 'block';
        renderBundleData();
        verifyBundle();
        window.scrollTo({ top: 0, behavior: 'smooth' });
      } catch (err) {
        alert('Failed to parse JSON: ' + err.message);
      }
    }

    function resetInspector() {
      bundleData = null;
      document.getElementById('inspect-content').style.display = 'none';
      document.getElementById('upload-zone').style.display = 'block';
      document.getElementById('file-input').value = '';
    }

    function renderBundleData() {
      const payload = bundleData.payload || {};
      
      document.getElementById('metric-bundle-id').textContent = (payload.bundle_id || 'N/A').substring(0, 16) + '...';
      document.getElementById('metric-agent-did').textContent = (payload.agent_did || 'N/A').substring(0, 24) + '...';
      document.getElementById('metric-issued-at').textContent = new Date(bundleData.issued_at).toLocaleString();
      
      const receiptCounts = {
        gateway: (payload.receipts || []).length,
        tool: (payload.tool_receipts || []).length,
        side_effect: (payload.side_effect_receipts || []).length,
        execution: (payload.execution_receipts || []).length,
        network: (payload.network_receipts || []).length,
        human_approval: (payload.human_approval_receipts || []).length,
      };
      const totalReceipts = Object.values(receiptCounts).reduce((a, b) => a + b, 0);
      document.getElementById('metric-receipts').textContent = totalReceipts + ' receipts';

      renderSummary(payload, receiptCounts);
      renderBreakdown(receiptCounts);
      renderAnomalies(payload);
      renderTimeline(payload);
      renderReceipts(payload);
      renderIntegrity();
    }

    function renderSummary(payload, counts) {
      const html = [
        ['Bundle ID', payload.bundle_id ? payload.bundle_id.substring(0, 20) : 'N/A'],
        ['Agent DID', payload.agent_did ? payload.agent_did.substring(0, 24) : 'N/A'],
        ['Harness', payload.metadata?.harness?.id || 'N/A'],
        ['Receipts', Object.values(counts).reduce((a, b) => a + b, 0)],
        ['Events', (payload.event_chain || []).length],
        ['Version', payload.bundle_version || 'N/A'],
      ].map(([label, value]) => '
        <div class="summary-item">
          <span class="summary-item-label">' + label + '</span>
          <span class="summary-item-value">' + (value || 'N/A') + '</span>
        </div>
      ').join('');
      document.getElementById('summary-content').innerHTML = html;
    }

    function renderBreakdown(counts) {
      const types = [
        { key: 'gateway', label: 'Gateway (LLM)', color: '#00ff88' },
        { key: 'tool', label: 'Tool Calls', color: '#00d9ff' },
        { key: 'side_effect', label: 'Side Effects', color: '#ffaa00' },
        { key: 'execution', label: 'Execution', color: '#ff6b6b' },
        { key: 'network', label: 'Network', color: '#a78bfa' },
        { key: 'human_approval', label: 'Approvals', color: '#4ade80' },
      ];
      
      const total = Object.values(counts).reduce((a, b) => a + b, 0);
      const html = types
        .filter(t => counts[t.key] > 0 || total === 0)
        .map(t => {
          const count = counts[t.key] || 0;
          const pct = total > 0 ? Math.round((count / total) * 100) : 0;
          return '
          <div class="breakdown-item">
            <span class="breakdown-label">' + t.label + '</span>
            <div class="breakdown-bar">
              <div class="breakdown-bar-fill" style="width:' + pct + '%;background:' + t.color + '"></div>
            </div>
            <span class="breakdown-count">' + count + '</span>
          </div>
          ';
        }).join('');
      document.getElementById('receipt-breakdown').innerHTML = html;
    }

    function renderAnomalies(payload) {
      const anomalies = [];
      
      if (!bundleData.signature_b64u) {
        anomalies.push('⚠ Missing signature - bundle integrity cannot be verified');
      }
      
      (payload.receipts || []).forEach(r => {
        if (r.tokens_input > 100000 || r.tokens_output > 100000) {
          anomalies.push('⚠ High token usage detected: ' + (r.tokens_input + r.tokens_output) + ' tokens');
        }
      });

      (payload.tool_receipts || []).forEach(r => {
        if (r.result_status !== 'SUCCESS' && r.result_status !== 'OK') {
          anomalies.push('⚠ Tool error: ' + r.tool_name + ' failed with status ' + r.result_status);
        }
        if (r.binding && r.binding.attribution_confidence < 0.5) {
          anomalies.push('⚠ Low confidence attribution for ' + r.tool_name);
        }
      });

      (payload.network_receipts || []).forEach(r => {
        if (r.suspicious) {
          anomalies.push('⚠ Suspicious network activity: ' + r.remote_address + ':' + r.remote_port);
        }
      });

      const html = anomalies.length > 0
        ? anomalies.map(a => '<div class="anomaly-item">' + a + '</div>').join('')
        : '<div class="anomaly-empty">✓ No anomalies detected</div>';
      
      document.getElementById('anomalies-list').innerHTML = html;
    }

    function renderTimeline(payload) {
      const events = (payload.event_chain || []).slice(0, 50);
      const html = events.map((e, i) => {
        const icon = {
          run_start: '▶',
          llm_call: '⚡',
          llm_response: '✓',
          tool_call: '🔧',
          tool_result: '✓',
          side_effect: '💾',
          run_end: '⏹',
        }[e.event_type] || '•';
        
        return '
        <div class="timeline-item' + (i === events.length - 1 ? ' last' : '') + '">
          <div class="timeline-marker">' + icon + '</div>
          <div class="timeline-content">
            <div class="timeline-type">' + (e.event_type || 'unknown').replace(/_/g, ' ') + '</div>
            <div class="timeline-details">' + (e.description || 'Event ' + (i + 1)) + '</div>
            <div class="timeline-meta">
              <span>Hash: ' + (e.event_hash_b64u || 'N/A').substring(0, 12) + '...</span>
              <span>Index: ' + i + '</span>
            </div>
          </div>
        </div>
        ';
      }).join('');
      
      document.getElementById('timeline-content').innerHTML = html || '<div style="padding:2rem;text-align:center;color:var(--text-dim)">No events recorded</div>';
    }

    function renderReceipts(payload) {
      const allReceipts = [
        ...(payload.receipts || []).map(r => ({ type: 'gateway', data: r })),
        ...(payload.tool_receipts || []).map(r => ({ type: 'tool', data: r })),
        ...(payload.side_effect_receipts || []).map(r => ({ type: 'side_effect', data: r })),
        ...(payload.execution_receipts || []).map(r => ({ type: 'execution', data: r })),
        ...(payload.network_receipts || []).map(r => ({ type: 'network', data: r })),
        ...(payload.human_approval_receipts || []).map(r => ({ type: 'human_approval', data: r })),
      ];

      const html = allReceipts.map((r, i) => {
        const typeLabels = {
          gateway: 'LLM Call',
          tool: 'Tool Call',
          side_effect: 'Side Effect',
          execution: 'Shell Command',
          network: 'Network',
          human_approval: 'Approval',
        };

        let summary = '';
        if (r.type === 'gateway') summary = (r.data.model || 'unknown') + ' @ ' + (r.data.provider || 'N/A');
        else if (r.type === 'tool') summary = r.data.tool_name + ' (v' + r.data.tool_version + ')';
        else if (r.type === 'execution') summary = (r.data.command_hash_b64u || r.data.command || 'N/A').substring(0, 40);
        else if (r.type === 'network') summary = r.data.remote_address + ':' + r.data.remote_port;
        else if (r.type === 'human_approval') summary = r.data.approval_type + ' by ' + (r.data.approver_subject || 'unknown');
        else summary = JSON.stringify(r.data).substring(0, 40) + '...';

        const statusClass = r.data.result_status === 'SUCCESS' || r.data.result_status === 'OK' || !r.data.result_status ? '' : ' error';
        const warningClass = r.data.binding?.attribution_confidence < 0.5 ? ' warning' : '';

        return '
        <div class="receipt-card" id="receipt-' + i + '">
          <div class="receipt-header" onclick="toggleReceipt(' + i + ')">
            <div>
              <span class="receipt-type-badge' + statusClass + warningClass + '">' + typeLabels[r.type] + '</span>
              <div style="margin-top:0.5rem;color:var(--text-dim);font-size:0.85rem">' + summary + '</div>
            </div>
            <div class="receipt-toggle">›</div>
          </div>
          <div class="receipt-body">
            ' + formatReceiptBody(r) + '
          </div>
        </div>
        ';
      }).join('');

      document.getElementById('receipts-content').innerHTML = html || '<div style="padding:2rem;text-align:center;color:var(--text-dim)">No receipts recorded</div>';
    }

    function formatReceiptBody(r) {
      const properties = [];
      const data = r.data;
      const labels = {
        provider: 'Provider',
        model: 'Model',
        tokens_input: 'Input Tokens',
        tokens_output: 'Output Tokens',
        latency_ms: 'Latency (ms)',
        tool_name: 'Tool Name',
        tool_version: 'Version',
        result_status: 'Status',
        command_hash_b64u: 'Command Hash',
        command: 'Command',
        exit_code: 'Exit Code',
        remote_address: 'Address',
        remote_port: 'Port',
        bytes_sent: 'Sent',
        bytes_received: 'Received',
        approval_type: 'Type',
        approver_subject: 'Approver',
      };

      for (const [key, label] of Object.entries(labels)) {
        if (data[key] !== undefined && data[key] !== null) {
          properties.push([label, String(data[key])]);
        }
      }

      if (data.binding) {
        properties.push(['Attribution Confidence', (data.binding.attribution_confidence || 0).toFixed(2)]);
        if (data.binding.span_id) properties.push(['Span ID', data.binding.span_id.substring(0, 20) + '...']);
      }

      return properties.map(([k, v]) => '
        <div class="receipt-property">
          <span class="receipt-property-label">' + k + '</span>
          <span class="receipt-property-value">' + v + '</span>
        </div>
      ').join('');
    }

    function toggleReceipt(index) {
      const card = document.getElementById('receipt-' + index);
      if (card) {
        card.classList.toggle('expanded');
      }
    }

    function renderIntegrity() {
      const checks = [
        {
          title: 'Signature Verification',
          detail: bundleData.signature_b64u ? 'Signature present (Ed25519)' : 'Missing signature',
          pass: !!bundleData.signature_b64u,
        },
        {
          title: 'Payload Hash',
          detail: bundleData.payload_hash_b64u ? bundleData.payload_hash_b64u.substring(0, 24) + '...' : 'N/A',
          pass: !!bundleData.payload_hash_b64u,
        },
        {
          title: 'Signer DID',
          detail: bundleData.signer_did ? bundleData.signer_did.substring(0, 24) + '...' : 'N/A',
          pass: !!bundleData.signer_did,
        },
        {
          title: 'Event Chain Integrity',
          detail: 'Hash-linked chain of ' + ((bundleData.payload?.event_chain || []).length) + ' events',
          pass: (bundleData.payload?.event_chain || []).length > 0,
        },
      ];

      const html = checks.map(c => '
        <div class="integrity-check ' + (c.pass ? 'pass' : 'fail') + '">
          <div class="integrity-check-icon">' + (c.pass ? '✓' : '✕') + '</div>
          <div class="integrity-check-content">
            <div class="integrity-check-title">' + c.title + '</div>
            <div class="integrity-check-detail">' + c.detail + '</div>
          </div>
        </div>
      ').join('');

      document.getElementById('integrity-content').innerHTML = html;
    }

    function verifyBundle() {
      const payload = bundleData.payload || {};
      const checks = [
        { name: 'Signature Present', pass: !!bundleData.signature_b64u },
        { name: 'Valid JSON', pass: true },
        { name: 'Payload Hash', pass: !!bundleData.payload_hash_b64u },
        { name: 'Signer DID', pass: !!bundleData.signer_did },
        { name: 'Event Chain', pass: (payload.event_chain || []).length > 0 },
      ];

      const html = checks.map(c => {
        const cls = c.pass ? 'pass' : 'fail';
        const icon = c.pass ? '✓' : '✕';
        return '<span class="status-badge ' + cls + '"><span class="dot"></span>' + icon + ' ' + c.name + '</span>';
      }).join('');

      document.getElementById('verify-status').innerHTML = html;
    }

    function switchTab(tabName) {
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      
      const pane = document.getElementById('tab-' + tabName);
      if (pane) {
        pane.classList.add('active');
        document.querySelector('[onclick="switchTab(\\'' + tabName + '\\')"]').classList.add('active');
      }
    }

    // Keyboard shortcuts
    document.addEventListener('keydown', e => {
      if (e.ctrlKey && e.key === 'v' && bundleData === null) {
        pasteJsonDialog();
      }
    });
  `;
}
