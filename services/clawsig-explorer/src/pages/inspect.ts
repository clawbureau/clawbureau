/**
 * Proof Bundle Inspector: GET /inspect
 *
 * Client-side proof bundle visualization tool.
 * Users upload/paste a proof_bundle.json and see:
 * - Envelope verification (DID, signature, timestamp)
 * - Receipt breakdown by type (gateway, tool, side-effect, etc.)
 * - Interactive event chain timeline
 * - Anomaly highlighting (suspicious networks, low attribution, etc.)
 * - Coverage metrics and integrity checks
 *
 * Design: Cyberpunk forensic terminal aesthetic with neon accents,
 * animated scan lines, and dramatic visual hierarchy.
 */

import { layout, esc, type PageMeta } from '../layout.js';

export function inspectPage(): string {
  const meta: PageMeta = {
    title: 'Proof Bundle Inspector',
    description: 'Upload or paste a proof bundle to inspect cryptographic receipts, trace the event chain, and verify integrity.',
    path: '/inspect',
    ogType: 'website',
  };

  const body = `
    <div class="inspector-hero">
      <div class="scan-line"></div>
      <div class="circuit-overlay"></div>
      <div class="hero-content">
        <h1 class="inspector-title">
          <span class="title-accent">//</span> PROOF BUNDLE INSPECTOR
        </h1>
        <p class="hero-subtitle">Cryptographic Forensics for AI Agent Executions</p>
        <div class="drop-zone" id="drop-zone">
          <div class="drop-zone-inner">
            <div class="drop-icon">
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                <polyline points="14,2 14,8 20,8"/>
                <path d="M12 18v-6"/>
                <path d="M9 15l3-3 3 3"/>
              </svg>
            </div>
            <p class="drop-text">Drop proof bundle here</p>
            <p class="drop-subtext">or click to upload / paste from clipboard</p>
            <input type="file" id="file-input" accept=".json,application/json" hidden>
          </div>
        </div>
      </div>
    </div>

    <div id="inspector-output" class="inspector-output"></div>

    <style>${inspectorStyles()}</style>
    <script>${inspectorScript()}</script>
  `;

  return layout(meta, body);
}

function inspectorStyles(): string {
  return /* css */ `
    .inspector-hero {
      position: relative;
      min-height: 340px;
      background: linear-gradient(180deg, #05080a 0%, #0a0f14 50%, #080c10 100%);
      border: 1px solid #1a2a35;
      border-radius: 12px;
      overflow: hidden;
      margin-bottom: 1.5rem;
    }

    .scan-line {
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 2px;
      background: linear-gradient(90deg, transparent, #00ffd5, #00ff88, transparent);
      animation: scan 3s ease-in-out infinite;
      opacity: 0.6;
    }

    @keyframes scan {
      0%, 100% { top: 0; opacity: 0; }
      10% { opacity: 0.6; }
      90% { opacity: 0.6; }
      100% { top: 100%; opacity: 0; }
    }

    .circuit-overlay {
      position: absolute;
      inset: 0;
      background-image:
        linear-gradient(90deg, rgba(0,255,136,0.03) 1px, transparent 1px),
        linear-gradient(rgba(0,255,136,0.03) 1px, transparent 1px);
      background-size: 60px 60px;
      pointer-events: none;
    }

    .hero-content {
      position: relative;
      z-index: 1;
      padding: 2.5rem;
      text-align: center;
    }

    .inspector-title {
      font-size: 1.75rem;
      font-weight: 700;
      letter-spacing: 0.15em;
      margin-bottom: 0.5rem;
      color: #e8f4f0;
      font-family: 'SF Mono', 'Fira Code', monospace;
    }

    .title-accent {
      color: #00ff88;
      margin-right: 0.5rem;
    }

    .hero-subtitle {
      color: #5a7a70;
      font-size: 0.9375rem;
      letter-spacing: 0.08em;
      margin-bottom: 2rem;
    }

    .drop-zone {
      max-width: 520px;
      margin: 0 auto;
      padding: 2rem;
      border: 2px dashed #2a4050;
      border-radius: 12px;
      background: rgba(0, 20, 30, 0.4);
      cursor: pointer;
      transition: all 0.25s ease;
    }

    .drop-zone:hover,
    .drop-zone.drag-over {
      border-color: #00ff88;
      background: rgba(0, 255, 136, 0.05);
      box-shadow: 0 0 30px rgba(0, 255, 136, 0.1);
    }

    .drop-zone.drag-over .drop-icon {
      transform: scale(1.15);
      color: #00ff88;
    }

    .drop-icon {
      color: #3a5a50;
      margin-bottom: 1rem;
      transition: all 0.25s ease;
    }

    .drop-text {
      color: #7a9a90;
      font-size: 1rem;
      font-weight: 600;
      margin-bottom: 0.25rem;
    }

    .drop-subtext {
      color: #4a6a60;
      font-size: 0.8125rem;
    }

    .inspector-output {
      display: none;
    }

    .inspector-output.active {
      display: block;
    }

    /* Envelope Card */
    .envelope-card {
      background: linear-gradient(135deg, #0a1015 0%, #0d151d 100%);
      border: 1px solid #1a2a35;
      border-radius: 12px;
      overflow: hidden;
      margin-bottom: 1.5rem;
    }

    .envelope-header {
      background: linear-gradient(90deg, rgba(0,255,136,0.1) 0%, transparent 50%, rgba(0,255,213,0.05) 100%);
      border-bottom: 1px solid #1a2a35;
      padding: 1.25rem 1.5rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      flex-wrap: wrap;
    }

    .envelope-title {
      font-size: 0.75rem;
      font-weight: 600;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: #00ff88;
    }

    .envelope-status {
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .status-indicator {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      animation: pulse-glow 2s ease-in-out infinite;
    }

    .status-indicator.verified {
      background: #00ff88;
      box-shadow: 0 0 12px rgba(0, 255, 136, 0.6);
    }

    .status-indicator.failed {
      background: #ff4466;
      box-shadow: 0 0 12px rgba(255, 68, 102, 0.6);
    }

    .status-indicator.pending {
      background: #ffaa00;
      box-shadow: 0 0 12px rgba(255, 170, 0, 0.6);
    }

    @keyframes pulse-glow {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.6; }
    }

    .envelope-body {
      padding: 1.5rem;
    }

    .envelope-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 1rem;
    }

    .env-field {
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid #1a2a35;
      border-radius: 8px;
      padding: 0.875rem 1rem;
    }

    .env-field-label {
      font-size: 0.6875rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: #4a6a60;
      margin-bottom: 0.35rem;
    }

    .env-field-value {
      font-family: 'SF Mono', 'Fira Code', monospace;
      font-size: 0.8125rem;
      color: #c8e8e0;
      word-break: break-all;
    }

    .env-field-value.did {
      color: #00ffd5;
    }

    .env-field-value.hash {
      color: #88aaff;
    }

    /* Metrics Bar */
    .metrics-bar {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 0.75rem;
      margin-bottom: 1.5rem;
    }

    .metric-tile {
      background: linear-gradient(135deg, #0d1318 0%, #0a1015 100%);
      border: 1px solid #1a2a35;
      border-radius: 10px;
      padding: 1rem;
      text-align: center;
      position: relative;
      overflow: hidden;
    }

    .metric-tile::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 2px;
      background: linear-gradient(90deg, transparent, var(--tile-accent, #00ff88), transparent);
      opacity: 0.6;
    }

    .metric-value {
      font-size: 1.75rem;
      font-weight: 700;
      font-family: 'SF Mono', monospace;
      color: var(--tile-accent, #00ff88);
    }

    .metric-label {
      font-size: 0.6875rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: #5a7a70;
      margin-top: 0.25rem;
    }

    .metric-tile.critical { --tile-accent: #ff4466; }
    .metric-tile.warning { --tile-accent: #ffaa00; }
    .metric-tile.info { --tile-accent: #00ffd5; }

    /* Event Chain Timeline */
    .timeline-section {
      background: linear-gradient(135deg, #0a0f14 0%, #080c10 100%);
      border: 1px solid #1a2a35;
      border-radius: 12px;
      overflow: hidden;
      margin-bottom: 1.5rem;
    }

    .timeline-header {
      padding: 1rem 1.5rem;
      border-bottom: 1px solid #1a2a35;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .timeline-title {
      font-size: 0.75rem;
      font-weight: 600;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: #00ffd5;
    }

    .timeline-legend {
      display: flex;
      gap: 1rem;
      font-size: 0.6875rem;
      color: #5a7a70;
    }

    .legend-item {
      display: flex;
      align-items: center;
      gap: 0.35rem;
    }

    .legend-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
    }

    .timeline-container {
      padding: 1.5rem;
      overflow-x: auto;
    }

    .timeline-track {
      display: flex;
      align-items: flex-start;
      gap: 0;
      min-width: max-content;
      position: relative;
      padding-top: 20px;
    }

    .timeline-track::before {
      content: '';
      position: absolute;
      top: 28px;
      left: 24px;
      right: 24px;
      height: 2px;
      background: linear-gradient(90deg, #00ff88, #00ffd5, #00ff88);
      opacity: 0.3;
    }

    .event-node {
      display: flex;
      flex-direction: column;
      align-items: center;
      min-width: 80px;
      position: relative;
      z-index: 1;
    }

    .event-dot {
      width: 16px;
      height: 16px;
      border-radius: 50%;
      border: 2px solid currentColor;
      background: #0a0f14;
      margin-bottom: 0.5rem;
      transition: all 0.2s ease;
      cursor: pointer;
    }

    .event-node:hover .event-dot {
      transform: scale(1.3);
      box-shadow: 0 0 12px currentColor;
    }

    .event-dot.llm { color: #00ff88; }
    .event-dot.tool { color: #88aaff; }
    .event-dot.side-effect { color: #ffaa00; }
    .event-dot.network { color: #ff4466; }
    .event-dot.human { color: #ff88cc; }
    .event-dot.start-end { color: #00ffd5; }

    .event-time {
      font-size: 0.625rem;
      color: #4a6a60;
      white-space: nowrap;
    }

    .event-label {
      font-size: 0.6875rem;
      color: #7a9a90;
      text-align: center;
      max-width: 70px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .event-tooltip {
      position: absolute;
      bottom: 100%;
      left: 50%;
      transform: translateX(-50%) translateY(-8px);
      background: #141a20;
      border: 1px solid #2a4050;
      border-radius: 8px;
      padding: 0.75rem;
      min-width: 200px;
      max-width: 320px;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.2s ease;
      z-index: 100;
      font-size: 0.75rem;
      box-shadow: 0 8px 24px rgba(0,0,0,0.5);
    }

    .event-node:hover .event-tooltip {
      opacity: 1;
    }

    /* Receipts Grid */
    .receipts-section {
      margin-bottom: 1.5rem;
    }

    .section-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 1rem;
    }

    .section-title {
      font-size: 0.75rem;
      font-weight: 600;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: #7a9a90;
    }

    .section-count {
      font-size: 0.6875rem;
      color: #4a6a60;
      padding: 0.25rem 0.75rem;
      background: rgba(0, 0, 0, 0.3);
      border-radius: 999px;
      border: 1px solid #1a2a35;
    }

    .receipt-tabs {
      display: flex;
      gap: 0.5rem;
      margin-bottom: 1rem;
      flex-wrap: wrap;
    }

    .receipt-tab {
      padding: 0.5rem 1rem;
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid #1a2a35;
      border-radius: 8px;
      color: #5a7a70;
      font-size: 0.8125rem;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .receipt-tab:hover {
      border-color: #2a4a50;
      color: #7a9a90;
    }

    .receipt-tab.active {
      background: rgba(0, 255, 136, 0.08);
      border-color: #00ff88;
      color: #00ff88;
    }

    .receipt-tab .count {
      font-size: 0.6875rem;
      margin-left: 0.5rem;
      padding: 0.1rem 0.4rem;
      background: rgba(255,255,255,0.1);
      border-radius: 4px;
    }

    .receipt-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
      gap: 0.75rem;
    }

    .receipt-card {
      background: rgba(0, 10, 15, 0.6);
      border: 1px solid #1a2a35;
      border-radius: 10px;
      padding: 1rem;
      transition: all 0.2s ease;
    }

    .receipt-card:hover {
      border-color: #2a4a50;
      background: rgba(0, 20, 30, 0.4);
    }

    .receipt-card.anomaly {
      border-color: #ff4466;
      background: rgba(255, 68, 102, 0.05);
    }

    .receipt-card.anomaly::before {
      content: '!';
      position: absolute;
      top: -8px;
      right: -8px;
      width: 18px;
      height: 18px;
      background: #ff4466;
      color: #000;
      font-weight: 700;
      font-size: 0.75rem;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .receipt-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 0.75rem;
    }

    .receipt-type {
      font-size: 0.6875rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: #00ff88;
      font-weight: 600;
    }

    .receipt-status {
      font-size: 0.6875rem;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      background: rgba(0, 255, 136, 0.15);
      color: #00ff88;
    }

    .receipt-status.error {
      background: rgba(255, 68, 102, 0.15);
      color: #ff4466;
    }

    .receipt-body {
      display: grid;
      gap: 0.4rem;
    }

    .receipt-field {
      display: flex;
      justify-content: space-between;
      gap: 0.5rem;
      font-size: 0.75rem;
    }

    .receipt-field-key {
      color: #4a6a60;
    }

    .receipt-field-value {
      color: #a8c8c0;
      font-family: 'SF Mono', monospace;
      font-size: 0.6875rem;
      text-align: right;
      word-break: break-all;
      max-width: 60%;
    }

    .receipt-confidence {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-top: 0.5rem;
      padding-top: 0.5rem;
      border-top: 1px solid #1a2a35;
    }

    .confidence-bar {
      flex: 1;
      height: 4px;
      background: #1a2a35;
      border-radius: 2px;
      overflow: hidden;
    }

    .confidence-fill {
      height: 100%;
      background: linear-gradient(90deg, #ff4466, #ffaa00, #00ff88);
      border-radius: 2px;
      transition: width 0.3s ease;
    }

    .confidence-label {
      font-size: 0.6875rem;
      color: #5a7a70;
      min-width: 60px;
      text-align: right;
    }

    /* Anomaly Panel */
    .anomaly-panel {
      background: linear-gradient(135deg, rgba(255, 68, 102, 0.1) 0%, rgba(255, 68, 102, 0.02) 100%);
      border: 1px solid rgba(255, 68, 102, 0.3);
      border-radius: 12px;
      padding: 1.25rem;
      margin-bottom: 1.5rem;
    }

    .anomaly-header {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 1rem;
    }

    .anomaly-icon {
      width: 32px;
      height: 32px;
      background: rgba(255, 68, 102, 0.2);
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #ff4466;
      font-size: 1.25rem;
    }

    .anomaly-title {
      font-size: 0.875rem;
      font-weight: 600;
      color: #ff4466;
    }

    .anomaly-subtitle {
      font-size: 0.6875rem;
      color: #8a6a70;
    }

    .anomaly-list {
      display: grid;
      gap: 0.5rem;
    }

    .anomaly-item {
      display: flex;
      align-items: flex-start;
      gap: 0.75rem;
      padding: 0.75rem;
      background: rgba(0, 0, 0, 0.3);
      border-radius: 8px;
      border-left: 3px solid #ff4466;
    }

    .anomaly-item-severity {
      font-size: 0.625rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      padding: 0.15rem 0.4rem;
      border-radius: 4px;
      font-weight: 600;
    }

    .anomaly-item-severity.high {
      background: rgba(255, 68, 102, 0.2);
      color: #ff4466;
    }

    .anomaly-item-severity.medium {
      background: rgba(255, 170, 0, 0.2);
      color: #ffaa00;
    }

    .anomaly-item-text {
      flex: 1;
      font-size: 0.8125rem;
      color: #c8a8b0;
    }

    /* Verification Panel */
    .verify-panel {
      background: linear-gradient(135deg, #0d151d 0%, #0a1015 100%);
      border: 2px solid #1a2a35;
      border-radius: 12px;
      overflow: hidden;
      margin-bottom: 1.5rem;
    }

    .verify-panel.verified { border-color: #00ff88; }
    .verify-panel.failed { border-color: #ff4466; }

    .verify-header {
      padding: 1rem 1.5rem;
      border-bottom: 1px solid #1a2a35;
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    .verify-icon {
      font-size: 1.25rem;
    }

    .verify-title {
      font-size: 0.8125rem;
      font-weight: 600;
      color: #c8e8e0;
    }

    .verify-body {
      padding: 1rem 1.5rem;
    }

    .verify-checks {
      display: grid;
      gap: 0.5rem;
    }

    .verify-check {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 0.5rem 0;
      border-bottom: 1px solid rgba(26, 42, 53, 0.5);
    }

    .verify-check:last-child {
      border-bottom: none;
    }

    .check-icon {
      width: 20px;
      text-align: center;
      font-size: 0.875rem;
    }

    .check-icon.pass { color: #00ff88; }
    .check-icon.fail { color: #ff4466; }
    .check-icon.pending { color: #ffaa00; }

    .check-label {
      flex: 1;
      font-size: 0.8125rem;
      color: #a8c8c0;
    }

    .check-detail {
      font-size: 0.6875rem;
      color: #5a7a70;
      font-family: 'SF Mono', monospace;
    }

    /* Raw JSON Toggle */
    .raw-toggle {
      margin-top: 1.5rem;
    }

    .raw-toggle-btn {
      width: 100%;
      padding: 0.75rem;
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid #1a2a35;
      border-radius: 8px;
      color: #5a7a70;
      font-size: 0.8125rem;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
    }

    .raw-toggle-btn:hover {
      border-color: #2a4a50;
      color: #7a9a90;
    }

    .raw-content {
      display: none;
      margin-top: 0.75rem;
      background: #050808;
      border: 1px solid #1a2a35;
      border-radius: 8px;
      overflow: hidden;
    }

    .raw-content.open {
      display: block;
    }

    .raw-content pre {
      padding: 1rem;
      margin: 0;
      font-family: 'SF Mono', monospace;
      font-size: 0.75rem;
      color: #88a0a8;
      overflow-x: auto;
      max-height: 400px;
    }

    /* Error State */
    .error-card {
      background: linear-gradient(135deg, rgba(255, 68, 102, 0.1) 0%, rgba(255, 68, 102, 0.02) 100%);
      border: 1px solid rgba(255, 68, 102, 0.4);
      border-radius: 12px;
      padding: 2rem;
      text-align: center;
    }

    .error-icon {
      font-size: 2.5rem;
      margin-bottom: 1rem;
    }

    .error-title {
      font-size: 1.125rem;
      font-weight: 600;
      color: #ff4466;
      margin-bottom: 0.5rem;
    }

    .error-message {
      color: #8a6a70;
      font-size: 0.875rem;
      margin-bottom: 1rem;
    }

    .error-reset {
      padding: 0.5rem 1rem;
      background: transparent;
      border: 1px solid #ff4466;
      color: #ff4466;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.8125rem;
      transition: all 0.2s ease;
    }

    .error-reset:hover {
      background: rgba(255, 68, 102, 0.1);
    }

    /* Responsive */
    @media (max-width: 640px) {
      .hero-content {
        padding: 1.5rem;
      }

      .inspector-title {
        font-size: 1.25rem;
        letter-spacing: 0.08em;
      }

      .drop-zone {
        padding: 1.5rem;
      }

      .metrics-bar {
        grid-template-columns: repeat(2, 1fr);
      }

      .timeline-container {
        padding: 1rem;
      }

      .receipt-grid {
        grid-template-columns: 1fr;
      }
    }

    @media (prefers-reduced-motion: reduce) {
      .scan-line {
        animation: none;
        opacity: 0.3;
        top: 50%;
      }

      .status-indicator {
        animation: none;
      }
    }
  `;
}

function inspectorScript(): string {
  return /* js */ `
  (function() {
    var dropZone = document.getElementById('drop-zone');
    var fileInput = document.getElementById('file-input');
    var output = document.getElementById('inspector-output');
    var currentBundle = null;

    // Drop zone interactions
    dropZone.addEventListener('click', function() {
      fileInput.click();
    });

    dropZone.addEventListener('dragover', function(e) {
      e.preventDefault();
      dropZone.classList.add('drag-over');
    });

    dropZone.addEventListener('dragleave', function() {
      dropZone.classList.remove('drag-over');
    });

    dropZone.addEventListener('drop', function(e) {
      e.preventDefault();
      dropZone.classList.remove('drag-over');
      var file = e.dataTransfer.files[0];
      if (file) handleFile(file);
    });

    fileInput.addEventListener('change', function(e) {
      var file = e.target.files[0];
      if (file) handleFile(file);
    });

    // Paste support
    document.addEventListener('paste', function(e) {
      var text = e.clipboardData.getData('text');
      if (text && text.trim().startsWith('{')) {
        try {
          var json = JSON.parse(text);
          processBundle(json);
        } catch (err) {
          showError('Failed to parse pasted JSON: ' + err.message);
        }
      }
    });

    function handleFile(file) {
      if (!file.type.includes('json') && !file.name.endsWith('.json')) {
        showError('Please upload a JSON proof bundle file.');
        return;
      }

      var reader = new FileReader();
      reader.onload = function(e) {
        try {
          var json = JSON.parse(e.target.result);
          processBundle(json);
        } catch (err) {
          showError('Failed to parse JSON: ' + err.message);
        }
      };
      reader.readAsText(file);
    }

    function processBundle(envelope) {
      currentBundle = envelope;
      var payload = envelope.payload || envelope;

      // Validate structure
      if (!envelope.signer_did && !payload.bundle_id) {
        showError('Invalid proof bundle: missing envelope or payload structure.');
        return;
      }

      // Extract data
      var data = extractData(envelope, payload);

      // Run verification
      var verification = verifyBundle(envelope, payload);

      // Detect anomalies
      var anomalies = detectAnomalies(data, payload);

      // Render output
      renderInspector(data, verification, anomalies, envelope);
    }

    function extractData(envelope, payload) {
      return {
        envelope: {
          signerDid: envelope.signer_did || 'N/A',
          signature: envelope.signature_b64u || 'N/A',
          issuedAt: envelope.issued_at || payload.metadata?.started_at || 'N/A',
          payloadHash: envelope.payload_hash_b64u || 'N/A',
        },
        bundle: {
          id: payload.bundle_id || 'unknown',
          version: payload.bundle_version || '1.0',
          agentDid: payload.agent_did || envelope.signer_did || 'N/A',
          harness: payload.metadata?.harness || {},
        },
        receipts: {
          gateway: payload.receipts || [],
          tool: payload.tool_receipts || [],
          sideEffect: payload.side_effect_receipts || [],
          execution: payload.execution_receipts || [],
          network: payload.network_receipts || [],
          human: payload.human_approval_receipts || [],
          vir: payload.vir_receipts || [],
          delegation: payload.delegation_receipts || [],
        },
        eventChain: payload.event_chain || [],
        coverage: payload.coverage_attestations || [],
      };
    }

    function verifyBundle(envelope, payload) {
      return {
        signature: null, // Will be checked async
        payloadHash: null, // Will be checked async
        eventChain: validateEventChain(payload.event_chain || []),
        receiptCount: countReceipts(payload),
        status: 'pending',
      };
    }

    function validateEventChain(chain) {
      if (!Array.isArray(chain) || chain.length === 0) {
        return { valid: true, note: 'No event chain present' };
      }

      var prevHash = null;
      for (var i = 0; i < chain.length; i++) {
        var ev = chain[i];
        if (i === 0) {
          if (ev.prev_event_hash_b64u !== null && ev.prev_event_hash_b64u !== '') {
            return { valid: false, note: 'Genesis event has non-null prev_hash' };
          }
        } else {
          if (ev.prev_event_hash_b64u !== prevHash) {
            return { valid: false, note: 'Chain linkage broken at event ' + i };
          }
        }
        prevHash = ev.event_hash_b64u;
      }

      return { valid: true, count: chain.length };
    }

    function countReceipts(payload) {
      var count = 0;
      var types = ['receipts', 'tool_receipts', 'side_effect_receipts', 'execution_receipts',
                   'network_receipts', 'human_approval_receipts', 'vir_receipts', 'delegation_receipts'];
      for (var i = 0; i < types.length; i++) {
        if (Array.isArray(payload[types[i]])) {
          count += payload[types[i]].length;
        }
      }
      return count;
    }

    function detectAnomalies(data, payload) {
      var anomalies = [];

      // Low attribution confidence
      ['tool', 'sideEffect'].forEach(function(type) {
        var receipts = data.receipts[type];
        if (Array.isArray(receipts)) {
          receipts.forEach(function(r, i) {
            var conf = r.binding?.attribution_confidence;
            if (conf !== undefined && conf < 0.7) {
              anomalies.push({
                severity: conf < 0.5 ? 'high' : 'medium',
                type: 'Low Attribution',
                message: type + ' receipt #' + i + ' has ' + (conf * 100).toFixed(0) + '% attribution confidence',
              });
            }
          });
        }
      });

      // Suspicious network connections
      var networkReceipts = data.receipts.network;
      if (Array.isArray(networkReceipts)) {
        networkReceipts.forEach(function(r, i) {
          if (r.suspicious) {
            anomalies.push({
              severity: 'high',
              type: 'Suspicious Network',
              message: 'Network connection to ' + (r.remote_address || 'unknown') + ':' + (r.remote_port || '?') + ' flagged as suspicious',
            });
          }
        });
      }

      // Model mismatch (VIR)
      var virReceipts = data.receipts.vir;
      if (Array.isArray(virReceipts)) {
        virReceipts.forEach(function(r, i) {
          if (r.model_claimed && r.model_observed && r.model_claimed !== r.model_observed) {
            anomalies.push({
              severity: 'high',
              type: 'Model Mismatch',
              message: 'VIR detected model mismatch: claimed ' + r.model_claimed + ', observed ' + r.model_observed,
            });
          }
        });
      }

      // Failed tool receipts
      var toolReceipts = data.receipts.tool;
      if (Array.isArray(toolReceipts)) {
        var failedTools = toolReceipts.filter(function(r) {
          return r.result_status === 'error' || r.result_status === 'fail';
        });
        if (failedTools.length > 0) {
          anomalies.push({
            severity: 'medium',
            type: 'Tool Failures',
            message: failedTools.length + ' tool invocation(s) failed',
          });
        }
      }

      // High latency gateway calls
      var gatewayReceipts = data.receipts.gateway;
      if (Array.isArray(gatewayReceipts)) {
        gatewayReceipts.forEach(function(r, i) {
          if (r.latency_ms && r.latency_ms > 30000) {
            anomalies.push({
              severity: 'medium',
              type: 'High Latency',
              message: 'Gateway call #' + (i+1) + ' took ' + (r.latency_ms / 1000).toFixed(1) + 's',
            });
          }
        });
      }

      return anomalies;
    }

    function renderInspector(data, verification, anomalies, envelope) {
      output.classList.add('active');

      var html = '';

      // Metrics bar
      html += renderMetricsBar(data, anomalies);

      // Anomaly panel (if any)
      if (anomalies.length > 0) {
        html += renderAnomalyPanel(anomalies);
      }

      // Envelope card
      html += renderEnvelopeCard(data.envelope, data.bundle, verification);

      // Event chain timeline
      if (data.eventChain.length > 0) {
        html += renderTimeline(data.eventChain);
      }

      // Receipts sections
      html += renderReceipts(data.receipts);

      // Raw JSON toggle
      html += renderRawToggle(envelope);

      // Verification panel
      html += renderVerifyPanel(verification);

      output.innerHTML = html;

      // Attach event listeners
      attachEventListeners();

      // Run async verification
      runAsyncVerification(envelope, verification);
    }

    function renderMetricsBar(data, anomalies) {
      var totalReceipts = countTotalReceipts(data.receipts);
      var eventCount = data.eventChain.length;

      return ''
        + '<div class="metrics-bar">'
        + '<div class="metric-tile"><div class="metric-value">' + totalReceipts + '</div><div class="metric-label">Receipts</div></div>'
        + '<div class="metric-tile"><div class="metric-value">' + eventCount + '</div><div class="metric-label">Events</div></div>'
        + '<div class="metric-tile"><div class="metric-value">' + data.receipts.gateway.length + '</div><div class="metric-label">LLM Calls</div></div>'
        + '<div class="metric-tile"><div class="metric-value">' + data.receipts.tool.length + '</div><div class="metric-label">Tool Invocations</div></div>'
        + (anomalies.length > 0 ? '<div class="metric-tile critical"><div class="metric-value">' + anomalies.length + '</div><div class="metric-label">Anomalies</div></div>' : '')
        + '</div>';
    }

    function countTotalReceipts(receipts) {
      var total = 0;
      Object.keys(receipts).forEach(function(k) {
        if (Array.isArray(receipts[k])) total += receipts[k].length;
      });
      return total;
    }

    function renderAnomalyPanel(anomalies) {
      var items = anomalies.map(function(a) {
        return ''
          + '<div class="anomaly-item">'
          + '<span class="anomaly-item-severity ' + a.severity + '">' + a.severity + '</span>'
          + '<span class="anomaly-item-text"><strong>' + esc(a.type) + ':</strong> ' + esc(a.message) + '</span>'
          + '</div>';
      }).join('');

      return ''
        + '<div class="anomaly-panel">'
        + '<div class="anomaly-header">'
        + '<div class="anomaly-icon">\\u26A0</div>'
        + '<div><div class="anomaly-title">' + anomalies.length + ' Anomalies Detected</div>'
        + '<div class="anomaly-subtitle">Review flagged items before trusting this execution</div></div>'
        + '</div>'
        + '<div class="anomaly-list">' + items + '</div>'
        + '</div>';
    }

    function renderEnvelopeCard(envelope, bundle, verification) {
      var statusClass = verification.status === 'verified' ? 'verified' :
                        verification.status === 'failed' ? 'failed' : 'pending';

      return ''
        + '<div class="envelope-card">'
        + '<div class="envelope-header">'
        + '<span class="envelope-title">Envelope</span>'
        + '<div class="envelope-status">'
        + '<span class="status-indicator ' + statusClass + '"></span>'
        + '<span>' + statusClass.toUpperCase() + '</span>'
        + '</div>'
        + '</div>'
        + '<div class="envelope-body">'
        + '<div class="envelope-grid">'
        + '<div class="env-field"><div class="env-field-label">Signer DID</div><div class="env-field-value did">' + esc(truncateDid(envelope.signerDid)) + '</div></div>'
        + '<div class="env-field"><div class="env-field-label">Bundle ID</div><div class="env-field-value">' + esc(envelope.bundle.id) + '</div></div>'
        + '<div class="env-field"><div class="env-field-label">Issued At</div><div class="env-field-value">' + esc(envelope.issuedAt) + '</div></div>'
        + '<div class="env-field"><div class="env-field-label">Bundle Version</div><div class="env-field-value">' + esc(envelope.bundle.version) + '</div></div>'
        + '<div class="env-field"><div class="env-field-label">Payload Hash</div><div class="env-field-value hash">' + esc(truncateHash(envelope.payloadHash)) + '</div></div>'
        + '<div class="env-field"><div class="env-field-label">Harness</div><div class="env-field-value">' + esc(bundle.harness.id || 'unknown') + ' v' + esc(bundle.harness.version || '?') + '</div></div>'
        + '</div>'
        + '</div>'
        + '</div>';
    }

    function renderTimeline(chain) {
      var events = chain.slice(0, 20).map(function(ev, i) {
        var type = ev.event_type || 'unknown';
        var dotClass = getEventClass(type);
        var label = formatEventLabel(type);
        var details = renderEventDetails(ev);

        return ''
          + '<div class="event-node">'
          + '<div class="event-dot ' + dotClass + '"></div>'
          + '<div class="event-label">' + esc(label) + '</div>'
          + '<div class="event-tooltip">' + details + '</div>'
          + '</div>';
      }).join('');

      var more = chain.length > 20 ? '<div style="margin-left:1rem;color:#5a7a70;font-size:0.75rem">+' + (chain.length - 20) + ' more</div>' : '';

      return ''
        + '<div class="timeline-section">'
        + '<div class="timeline-header">'
        + '<span class="timeline-title">Event Chain</span>'
        + '<div class="timeline-legend">'
        + '<span class="legend-item"><span class="legend-dot" style="background:#00ff88"></span>LLM</span>'
        + '<span class="legend-item"><span class="legend-dot" style="background:#88aaff"></span>Tool</span>'
        + '<span class="legend-item"><span class="legend-dot" style="background:#ffaa00"></span>Effect</span>'
        + '<span class="legend-item"><span class="legend-dot" style="background:#ff4466"></span>Network</span>'
        + '</div>'
        + '</div>'
        + '<div class="timeline-container">'
        + '<div class="timeline-track">' + events + more + '</div>'
        + '</div>'
        + '</div>';
    }

    function getEventClass(type) {
      if (type.includes('llm')) return 'llm';
      if (type.includes('tool')) return 'tool';
      if (type.includes('side_effect') || type.includes('effect')) return 'side-effect';
      if (type.includes('network')) return 'network';
      if (type.includes('human')) return 'human';
      return 'start-end';
    }

    function formatEventLabel(type) {
      var labels = {
        'run_start': 'START',
        'run_end': 'END',
        'llm_call': 'LLM Call',
        'llm_response': 'LLM Res',
        'tool_call': 'Tool Call',
        'tool_result': 'Tool Res',
        'side_effect': 'Effect',
        'human_approval': 'Human',
      };
      return labels[type] || type.replace(/_/g, ' ').slice(0, 10);
    }

    function renderEventDetails(ev) {
      var html = '<div style="font-size:0.75rem;color:#c8e8e0">';
      html += '<div style="margin-bottom:0.5rem;color:#00ff88">' + esc(ev.event_type || 'unknown') + '</div>';
      if (ev.event_hash_b64u) {
        html += '<div style="color:#5a7a70">Hash:</div><div style="font-family:monospace;font-size:0.6875rem;color:#88aaff">' + esc(truncateHash(ev.event_hash_b64u)) + '</div>';
      }
      html += '</div>';
      return html;
    }

    function renderReceipts(receipts) {
      var tabs = [];
      var sections = [];

      var types = [
        { key: 'gateway', label: 'Gateway', color: '#00ff88' },
        { key: 'tool', label: 'Tool', color: '#88aaff' },
        { key: 'sideEffect', label: 'Side Effect', color: '#ffaa00' },
        { key: 'execution', label: 'Execution', color: '#00ffd5' },
        { key: 'network', label: 'Network', color: '#ff4466' },
        { key: 'human', label: 'Human', color: '#ff88cc' },
        { key: 'vir', label: 'VIR', color: '#aa88ff' },
      ];

      types.forEach(function(t) {
        var arr = receipts[t.key];
        if (Array.isArray(arr) && arr.length > 0) {
          tabs.push('<button class="receipt-tab' + (tabs.length === 0 ? ' active' : '') + '" data-tab="' + t.key + '">' + t.label + '<span class="count">' + arr.length + '</span></button>');
          sections.push('<div class="receipt-section" id="section-' + t.key + '" style="' + (tabs.length === 1 ? '' : 'display:none') + '">' + renderReceiptGrid(arr, t.key) + '</div>');
        }
      });

      if (tabs.length === 0) {
        return '<div class="receipts-section"><div class="section-header"><span class="section-title">Receipts</span></div><p class="dim" style="font-size:0.875rem">No receipts found in this bundle.</p></div>';
      }

      return ''
        + '<div class="receipts-section">'
        + '<div class="section-header"><span class="section-title">Receipts</span></div>'
        + '<div class="receipt-tabs">' + tabs.join('') + '</div>'
        + sections.join('')
        + '</div>';
    }

    function renderReceiptGrid(receipts, type) {
      var cards = receipts.slice(0, 50).map(function(r, i) {
        return renderReceiptCard(r, type, i);
      }).join('');

      return '<div class="receipt-grid">' + cards + '</div>';
    }

    function renderReceiptCard(r, type, index) {
      var fields = [];
      var hasConfidence = false;
      var confidence = null;

      if (type === 'gateway') {
        fields.push({ key: 'Provider', value: r.provider || 'unknown' });
        fields.push({ key: 'Model', value: r.model || 'unknown' });
        if (r.tokens_input) fields.push({ key: 'Input Tokens', value: r.tokens_input });
        if (r.tokens_output) fields.push({ key: 'Output Tokens', value: r.tokens_output });
        if (r.latency_ms) fields.push({ key: 'Latency', value: r.latency_ms + 'ms' });
      } else if (type === 'tool') {
        fields.push({ key: 'Tool', value: r.tool_name || 'unknown' });
        fields.push({ key: 'Status', value: r.result_status || 'unknown' });
        if (r.latency_ms) fields.push({ key: 'Latency', value: r.latency_ms + 'ms' });
        if (r.binding) {
          confidence = r.binding.attribution_confidence;
          hasConfidence = confidence !== undefined;
        }
      } else if (type === 'sideEffect') {
        fields.push({ key: 'Class', value: r.effect_class || 'unknown' });
        fields.push({ key: 'Status', value: r.response_status || 'unknown' });
        if (r.bytes_written) fields.push({ key: 'Bytes Written', value: formatBytes(r.bytes_written) });
        if (r.binding) {
          confidence = r.binding.attribution_confidence;
          hasConfidence = confidence !== undefined;
        }
      } else if (type === 'execution') {
        fields.push({ key: 'Command', value: truncate(r.command || r.command_hash_b64u || 'unknown', 40) });
        fields.push({ key: 'Exit Code', value: r.exit_code !== undefined ? r.exit_code : 'N/A' });
        if (r.duration_ms) fields.push({ key: 'Duration', value: r.duration_ms + 'ms' });
      } else if (type === 'network') {
        fields.push({ key: 'Address', value: (r.remote_address || '?') + ':' + (r.remote_port || '?') });
        fields.push({ key: 'Protocol', value: r.protocol || 'unknown' });
        if (r.bytes_sent || r.bytes_received) {
          fields.push({ key: 'Traffic', value: formatBytes(r.bytes_sent || 0) + ' / ' + formatBytes(r.bytes_received || 0) });
        }
        if (r.suspicious) fields.push({ key: 'Flagged', value: 'SUSPICIOUS' });
      } else if (type === 'human') {
        fields.push({ key: 'Type', value: r.approval_type || 'unknown' });
        fields.push({ key: 'Approver', value: truncate(r.approver_subject || 'unknown', 24) });
        fields.push({ key: 'Method', value: r.approver_method || 'unknown' });
      } else if (type === 'vir') {
        fields.push({ key: 'Claimed', value: r.model_claimed || 'N/A' });
        fields.push({ key: 'Observed', value: r.model_observed || 'N/A' });
        if (r.model_claimed !== r.model_observed) {
          fields.push({ key: 'Mismatch', value: 'DETECTED' });
        }
      }

      var isAnomaly = (type === 'network' && r.suspicious) ||
                      (type === 'vir' && r.model_claimed !== r.model_observed) ||
                      (type === 'tool' && (r.result_status === 'error' || r.result_status === 'fail'));

      var statusClass = isAnomaly ? 'error' : '';

      var fieldsHtml = fields.map(function(f) {
        return '<div class="receipt-field"><span class="receipt-field-key">' + esc(f.key) + '</span><span class="receipt-field-value">' + esc(f.value) + '</span></div>';
      }).join('');

      var confidenceHtml = '';
      if (hasConfidence && confidence !== null) {
        var pct = Math.round(confidence * 100);
        var color = confidence < 0.5 ? '#ff4466' : confidence < 0.7 ? '#ffaa00' : '#00ff88';
        confidenceHtml = '<div class="receipt-confidence"><span class="confidence-label">Attribution</span><div class="confidence-bar"><div class="confidence-fill" style="width:' + pct + '%;background:' + color + '"></div></div><span style="font-size:0.6875rem;color:' + color + '">' + pct + '%</span></div>';
      }

      return ''
        + '<div class="receipt-card' + (isAnomaly ? ' anomaly' : '') + '" style="position:relative">'
        + '<div class="receipt-header"><span class="receipt-type">' + esc(type.toUpperCase()) + '</span><span class="receipt-status ' + statusClass + '">#' + (index + 1) + '</span></div>'
        + '<div class="receipt-body">' + fieldsHtml + confidenceHtml + '</div>'
        + '</div>';
    }

    function renderRawToggle(envelope) {
      var json = JSON.stringify(envelope, null, 2);
      return ''
        + '<div class="raw-toggle">'
        + '<button class="raw-toggle-btn" onclick="var c=this.nextElementSibling;c.classList.toggle(\\'open\\');this.querySelector(\\'.arrow\\').textContent=c.classList.contains(\\'open\\')?\\'\\u25BC\\':\\'\\u25B6\\'">'
        + '<span class="arrow">\\u25B6</span> View Raw JSON</button>'
        + '<div class="raw-content"><pre>' + esc(json) + '</pre></div>'
        + '</div>';
    }

    function renderVerifyPanel(verification) {
      var sigStatus = verification.signature === null ? 'pending' : verification.signature ? 'pass' : 'fail';
      var hashStatus = verification.payloadHash === null ? 'pending' : verification.payloadHash ? 'pass' : 'fail';
      var chainStatus = verification.eventChain.valid ? 'pass' : 'fail';

      var sigIcon = sigStatus === 'pass' ? '\\u2705' : sigStatus === 'fail' ? '\\u274C' : '\\u23F3';
      var hashIcon = hashStatus === 'pass' ? '\\u2705' : hashStatus === 'fail' ? '\\u274C' : '\\u23F3';
      var chainIcon = chainStatus === 'pass' ? '\\u2705' : '\\u274C';

      return ''
        + '<div class="verify-panel" id="verify-panel">'
        + '<div class="verify-header">'
        + '<span class="verify-icon" id="verify-icon">\\u23F3</span>'
        + '<span class="verify-title" id="verify-title">Client-Side Verification</span>'
        + '</div>'
        + '<div class="verify-body">'
        + '<div class="verify-checks">'
        + '<div class="verify-check"><span class="check-icon ' + sigStatus + '" id="check-sig-icon">' + sigIcon + '</span><span class="check-label">Ed25519 Signature</span><span class="check-detail" id="check-sig-detail">' + (sigStatus === 'pending' ? 'Checking...' : '') + '</span></div>'
        + '<div class="verify-check"><span class="check-icon ' + hashStatus + '" id="check-hash-icon">' + hashIcon + '</span><span class="check-label">Payload Hash (SHA-256)</span><span class="check-detail" id="check-hash-detail">' + (hashStatus === 'pending' ? 'Checking...' : '') + '</span></div>'
        + '<div class="verify-check"><span class="check-icon ' + chainStatus + '">' + chainIcon + '</span><span class="check-label">Event Chain Linkage</span><span class="check-detail">' + (verification.eventChain.note || verification.eventChain.count + ' events') + '</span></div>'
        + '<div class="verify-check"><span class="check-icon pass">\\u2705</span><span class="check-label">Receipts Present</span><span class="check-detail">' + verification.receiptCount + ' total</span></div>'
        + '</div>'
        + '<p id="verify-result" style="margin-top:1rem;font-size:0.8125rem;color:#5a7a70"></p>'
        + '</div>'
        + '</div>';
    }

    function attachEventListeners() {
      var tabs = document.querySelectorAll('.receipt-tab');
      tabs.forEach(function(tab) {
        tab.addEventListener('click', function() {
          tabs.forEach(function(t) { t.classList.remove('active'); });
          tab.classList.add('active');
          document.querySelectorAll('.receipt-section').forEach(function(s) { s.style.display = 'none'; });
          var section = document.getElementById('section-' + tab.getAttribute('data-tab'));
          if (section) section.style.display = 'block';
        });
      });
    }

    function runAsyncVerification(envelope, verification) {
      var panel = document.getElementById('verify-panel');
      if (!panel) return;

      // Check payload hash
      try {
        var payloadJson = JSON.stringify(envelope.payload);
        var payloadBytes = new TextEncoder().encode(payloadJson);
        crypto.subtle.digest('SHA-256', payloadBytes).then(function(hashBuf) {
          var computedHash = b64uEncode(new Uint8Array(hashBuf));
          var match = computedHash === envelope.payload_hash_b64u;
          updateCheck('hash', match, match ? 'Match' : 'Mismatch');
          verification.payloadHash = match;

          // Then verify signature
          if (match) {
            verifySignature(envelope, verification);
          } else {
            setFinalStatus(verification);
          }
        }).catch(function(err) {
          updateCheck('hash', false, 'Error: ' + err.message);
          setFinalStatus(verification);
        });
      } catch (err) {
        updateCheck('hash', false, 'Error');
        setFinalStatus(verification);
      }
    }

    function verifySignature(envelope, verification) {
      var pubBytes = extractPubKeyFromDidKey(envelope.signer_did);
      if (!pubBytes) {
        updateCheck('sig', null, 'Cannot extract key');
        verification.signature = false;
        setFinalStatus(verification);
        return;
      }

      crypto.subtle.importKey('raw', pubBytes.buffer, { name: 'Ed25519' }, false, ['verify'])
        .then(function(pubKey) {
          var sigBytes = b64uDecode(envelope.signature_b64u);
          var msgBytes = new TextEncoder().encode(envelope.payload_hash_b64u);
          return crypto.subtle.verify('Ed25519', pubKey, sigBytes, msgBytes);
        })
        .then(function(valid) {
          updateCheck('sig', valid, valid ? 'Valid' : 'Invalid');
          verification.signature = valid;
          setFinalStatus(verification);
        })
        .catch(function(err) {
          // Ed25519 not supported in this browser
          updateCheck('sig', null, 'Browser unsupported');
          verification.signature = null;
          setFinalStatus(verification);
        });
    }

    function updateCheck(type, ok, detail) {
      var iconEl = document.getElementById('check-' + type + '-icon');
      var detailEl = document.getElementById('check-' + type + '-detail');
      if (iconEl) {
        iconEl.className = 'check-icon ' + (ok === true ? 'pass' : ok === false ? 'fail' : 'pending');
        iconEl.textContent = ok === true ? '\\u2705' : ok === false ? '\\u274C' : '\\u2796';
      }
      if (detailEl) detailEl.textContent = detail || '';
    }

    function setFinalStatus(verification) {
      var panel = document.getElementById('verify-panel');
      var icon = document.getElementById('verify-icon');
      var title = document.getElementById('verify-title');
      var result = document.getElementById('verify-result');

      var allPass = verification.signature === true && verification.payloadHash === true && verification.eventChain.valid;

      if (allPass) {
        panel.classList.add('verified');
        panel.classList.remove('failed');
        icon.textContent = '\\u2705';
        title.textContent = 'Verified by Your Browser';
        result.className = 'pass';
        result.textContent = 'All cryptographic checks passed. Trust nothing, verify everything.';
      } else if (verification.signature === false || verification.payloadHash === false) {
        panel.classList.add('failed');
        panel.classList.remove('verified');
        icon.textContent = '\\u274C';
        title.textContent = 'Verification Failed';
        result.className = 'fail';
        result.textContent = 'One or more checks failed. Do not trust this bundle.';
      } else {
        icon.textContent = '\\u2796';
        title.textContent = 'Partial Verification';
        result.className = 'warn';
        result.textContent = 'Some checks could not be completed. Review details above.';
      }
    }

    function showError(message) {
      output.classList.add('active');
      output.innerHTML = ''
        + '<div class="error-card">'
        + '<div class="error-icon">\\u274C</div>'
        + '<div class="error-title">Failed to Load Bundle</div>'
        + '<div class="error-message">' + esc(message) + '</div>'
        + '<button class="error-reset" onclick="location.reload()">Try Again</button>'
        + '</div>';
    }

    // Utility functions
    function esc(s) {
      if (!s) return '';
      return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function truncate(s, max) {
      if (!s) return '';
      s = String(s);
      return s.length > max ? s.slice(0, max) + '...' : s;
    }

    function truncateHash(h) {
      if (!h) return 'N/A';
      return h.length > 24 ? h.slice(0, 16) + '...' + h.slice(-6) : h;
    }

    function truncateDid(did) {
      if (!did) return 'N/A';
      return did.length > 32 ? did.slice(0, 20) + '...' + did.slice(-8) : did;
    }

    function formatBytes(n) {
      if (!n || n < 0) return '0 B';
      var units = ['B', 'KB', 'MB', 'GB'];
      var i = 0;
      while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
      return n.toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
    }

    function b64uDecode(s) {
      var b64 = s.replace(/-/g, '+').replace(/_/g, '/');
      var padded = b64 + '='.repeat((4 - b64.length % 4) % 4);
      var bin = atob(padded);
      var bytes = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return bytes;
    }

    function b64uEncode(bytes) {
      var bin = '';
      for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
    }

    function extractPubKeyFromDidKey(did) {
      if (!did || !did.startsWith('did:key:z')) return null;
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
      var ALPHA = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
      var bytes = [0];
      for (var ci = 0; ci < str.length; ci++) {
        var val = ALPHA.indexOf(str[ci]);
        if (val === -1) throw new Error('Invalid base58');
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
        if (str[ci] !== '1') break;
        bytes.push(0);
      }
      return new Uint8Array(bytes.reverse());
    }
  })();
  `;
}
