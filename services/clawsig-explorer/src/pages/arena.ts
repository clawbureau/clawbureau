import { esc, fmtNum, layout, relativeTime, statusBadge, type PageMeta } from '../layout.js';
import type { ArenaContenderView, ArenaMissionSummaryView, ArenaReportView } from '../api.js';

interface ArenaIndexItem {
  arena_id: string;
  bounty_id: string;
  contract_id: string;
  generated_at: string;
  winner_contender_id: string;
  reason_code: string;
}

// ─── Arena design-system CSS ────────────────────────────────────────────────

function arenaCSS(): string {
  return `
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@400;600;700;800&family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
/* ── Arena design system ── */
:root {
  --a-bg:            #07070a;
  --a-surface:       #101016;
  --a-panel:         #16161e;
  --a-panel2:        #1c1c28;
  --a-teal:          #00d4aa;
  --a-teal-glow:     rgba(0,212,170,0.25);
  --a-teal-glow2:    rgba(0,212,170,0.08);
  --a-red:           #ff2a5f;
  --a-red-glow:      rgba(255,42,95,0.25);
  --a-red-glow2:     rgba(255,42,95,0.08);
  --a-gold:          #f5c842;
  --a-gold-glow:     rgba(245,200,66,0.3);
  --a-text:          #f0f0f5;
  --a-dim:           #8b8b99;
  --a-border:        #22222d;
  --a-border2:       #2e2e3e;
  --a-display:       'Chakra Petch', sans-serif;
  --a-body:          'Outfit', sans-serif;
  --a-mono:          'JetBrains Mono', monospace;
}

/* override layout container for arena pages */
main .container { max-width: 1200px !important; }

/* ── Noise overlay ── */
.arena-noise {
  position: relative;
  overflow: hidden;
}
.arena-noise::before {
  content: '';
  position: absolute;
  inset: 0;
  background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.75' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.04'/%3E%3C/svg%3E");
  pointer-events: none;
  z-index: 0;
  border-radius: inherit;
}

/* ── Section headers ── */
.arena-section-label {
  font-family: var(--a-display);
  font-size: 0.65rem;
  font-weight: 700;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: var(--a-teal);
  margin-bottom: 0.35rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.arena-section-label::before {
  content: '';
  display: inline-block;
  width: 3px;
  height: 1em;
  background: var(--a-teal);
  border-radius: 2px;
  box-shadow: 0 0 8px var(--a-teal-glow);
}
.arena-section-title {
  font-family: var(--a-display);
  font-size: 1.15rem;
  font-weight: 700;
  color: var(--a-text);
  margin-bottom: 0.2rem;
}
.arena-card {
  background: var(--a-panel);
  border: 1px solid var(--a-border);
  border-radius: 12px;
  padding: 1.5rem;
  margin-bottom: 1rem;
  position: relative;
}
.arena-card:hover {
  border-color: var(--a-border2);
}
.arena-card-accent-teal {
  border-color: rgba(0,212,170,0.3);
  box-shadow: 0 0 0 1px rgba(0,212,170,0.1), inset 0 1px 0 rgba(0,212,170,0.08);
}
.arena-card-accent-red {
  border-color: rgba(255,42,95,0.3);
  box-shadow: 0 0 0 1px rgba(255,42,95,0.1), inset 0 1px 0 rgba(255,42,95,0.08);
}

/* ── VS Hero Screen ── */
.arena-hero-wrap {
  background: var(--a-bg);
  border: 1px solid var(--a-border);
  border-radius: 16px;
  padding: 2.5rem 1.5rem;
  margin-bottom: 2rem;
  position: relative;
  overflow: hidden;
}
.arena-hero-wrap::after {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 2px;
  background: linear-gradient(90deg, transparent 0%, var(--a-teal) 30%, var(--a-red) 70%, transparent 100%);
}
.arena-hero-title {
  font-family: var(--a-display);
  font-size: 0.65rem;
  font-weight: 700;
  letter-spacing: 0.22em;
  text-transform: uppercase;
  color: var(--a-dim);
  text-align: center;
  margin-bottom: 2rem;
}
.vs-grid {
  display: grid;
  grid-template-columns: 1fr auto 1fr;
  gap: 0;
  align-items: stretch;
}
.vs-col {
  background: var(--a-surface);
  border: 1px solid var(--a-border);
  border-radius: 12px;
  padding: 1.75rem 1.5rem;
  display: flex;
  flex-direction: column;
  gap: 1rem;
  transition: box-shadow 0.3s;
  position: relative;
  overflow: hidden;
}
.vs-col-winner {
  border-color: rgba(0,212,170,0.45);
  box-shadow: 0 0 40px rgba(0,212,170,0.12), inset 0 0 60px rgba(0,212,170,0.04);
}
.vs-col-winner::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 2px;
  background: linear-gradient(90deg, transparent, var(--a-teal), transparent);
  animation: pulse-line 2.5s ease-in-out infinite;
}
.vs-col-loser {
  opacity: 0.75;
}
.vs-col-fail {
  border-color: rgba(255,42,95,0.3);
}
@keyframes pulse-line {
  0%, 100% { opacity: 0.6; }
  50%       { opacity: 1; }
}
.vs-divider {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 80px;
  flex-shrink: 0;
}
.vs-badge {
  font-family: var(--a-display);
  font-size: 1.6rem;
  font-weight: 800;
  color: var(--a-dim);
  letter-spacing: 0.05em;
  text-shadow: 0 0 20px rgba(139,139,153,0.3);
  position: relative;
}
.vs-badge::before, .vs-badge::after {
  content: '';
  display: block;
  width: 1px;
  height: 40px;
  background: linear-gradient(to bottom, transparent, var(--a-border), transparent);
  margin: 0.5rem auto;
}
.vs-crown {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  background: rgba(0,212,170,0.12);
  border: 1px solid rgba(0,212,170,0.4);
  border-radius: 999px;
  padding: 0.2rem 0.7rem;
  font-family: var(--a-display);
  font-size: 0.65rem;
  font-weight: 700;
  letter-spacing: 0.1em;
  color: var(--a-teal);
  text-transform: uppercase;
  animation: crown-pulse 2s ease-in-out infinite;
  margin-bottom: 0.5rem;
  width: fit-content;
}
@keyframes crown-pulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(0,212,170,0.3); }
  50%       { box-shadow: 0 0 0 6px rgba(0,212,170,0); }
}
.vs-model-name {
  font-family: var(--a-display);
  font-size: 1.3rem;
  font-weight: 800;
  color: var(--a-text);
  line-height: 1.1;
  margin-bottom: 0.25rem;
  word-break: break-word;
}
.vs-harness {
  font-family: var(--a-mono);
  font-size: 0.72rem;
  color: var(--a-dim);
}
.vs-score-wrap {
  margin: 0.5rem 0;
}
.vs-score-label {
  font-family: var(--a-mono);
  font-size: 0.65rem;
  color: var(--a-dim);
  letter-spacing: 0.1em;
  text-transform: uppercase;
  margin-bottom: 0.4rem;
}
.vs-score-num {
  font-family: var(--a-display);
  font-size: 3.5rem;
  font-weight: 800;
  line-height: 1;
  margin-bottom: 0.5rem;
  background: linear-gradient(135deg, var(--a-teal) 0%, #00ffcc 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  animation: score-reveal 1.2s cubic-bezier(0.22,1,0.36,1) both;
}
.vs-score-num-loser {
  background: linear-gradient(135deg, var(--a-dim) 0%, #555566 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}
.vs-score-num-fail {
  background: linear-gradient(135deg, var(--a-red) 0%, #ff6688 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}
@keyframes score-reveal {
  from { opacity: 0; transform: translateY(12px) scale(0.92); }
  to   { opacity: 1; transform: translateY(0) scale(1); }
}
.vs-score-bar-track {
  height: 6px;
  background: var(--a-border);
  border-radius: 3px;
  overflow: hidden;
}
.vs-score-bar-fill {
  height: 100%;
  border-radius: 3px;
  background: linear-gradient(90deg, var(--a-teal), #00ffcc);
  box-shadow: 0 0 8px var(--a-teal-glow);
  transform-origin: left;
  animation: bar-fill 1.4s cubic-bezier(0.22,1,0.36,1) both;
  animation-delay: 0.3s;
}
.vs-score-bar-fill-loser {
  background: linear-gradient(90deg, #44445a, #666677);
  box-shadow: none;
}
.vs-score-bar-fill-fail {
  background: linear-gradient(90deg, var(--a-red), #ff6688);
  box-shadow: 0 0 8px var(--a-red-glow);
}
@keyframes bar-fill {
  from { width: 0 !important; }
}
.vs-gate {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  font-family: var(--a-display);
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  padding: 0.22rem 0.6rem;
  border-radius: 4px;
}
.vs-gate-pass {
  background: rgba(0,212,170,0.1);
  color: var(--a-teal);
  border: 1px solid rgba(0,212,170,0.35);
}
.vs-gate-fail {
  background: rgba(255,42,95,0.1);
  color: var(--a-red);
  border: 1px solid rgba(255,42,95,0.35);
}
.vs-evidence-links {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
  margin-top: 0.25rem;
}
.vs-ev-link {
  font-family: var(--a-mono);
  font-size: 0.65rem;
  color: var(--a-dim);
  background: var(--a-panel);
  border: 1px solid var(--a-border);
  border-radius: 4px;
  padding: 0.18rem 0.5rem;
  text-decoration: none;
  transition: all 0.2s;
}
.vs-ev-link:hover {
  color: var(--a-teal);
  border-color: rgba(0,212,170,0.4);
  text-decoration: none;
}
.vs-metrics-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.4rem;
}
.vs-metric-chip {
  background: var(--a-panel);
  border: 1px solid var(--a-border);
  border-radius: 6px;
  padding: 0.35rem 0.5rem;
}
.vs-metric-label {
  font-family: var(--a-mono);
  font-size: 0.62rem;
  color: var(--a-dim);
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
.vs-metric-val {
  font-family: var(--a-mono);
  font-size: 0.78rem;
  color: var(--a-text);
  font-weight: 600;
}
/* more contenders strip (>2 contenders) */
.vs-more-strip {
  display: flex;
  gap: 1rem;
  margin-top: 1.5rem;
  flex-wrap: wrap;
}
.vs-more-card {
  flex: 1;
  min-width: 200px;
  background: var(--a-surface);
  border: 1px solid var(--a-border);
  border-radius: 10px;
  padding: 1rem 1.25rem;
  display: flex;
  align-items: center;
  gap: 1rem;
}
.vs-more-score {
  font-family: var(--a-display);
  font-size: 1.8rem;
  font-weight: 800;
  color: var(--a-dim);
  animation: score-reveal 1.4s cubic-bezier(0.22,1,0.36,1) both;
  animation-delay: 0.6s;
}

/* ── Live Output Iframe Viewer ── */
.iframe-viewer {
  background: var(--a-panel);
  border: 1px solid var(--a-border);
  border-radius: 12px;
  overflow: hidden;
  margin-bottom: 1rem;
}
.iframe-tab-bar {
  display: flex;
  gap: 0;
  background: var(--a-surface);
  border-bottom: 1px solid var(--a-border);
  padding: 0 1rem;
  overflow-x: auto;
}
.iframe-tab {
  font-family: var(--a-display);
  font-size: 0.72rem;
  font-weight: 600;
  color: var(--a-dim);
  padding: 0.75rem 1.25rem;
  cursor: pointer;
  border-bottom: 2px solid transparent;
  white-space: nowrap;
  transition: all 0.2s;
  background: none;
  border-top: none;
  border-left: none;
  border-right: none;
  letter-spacing: 0.05em;
  text-transform: uppercase;
}
.iframe-tab:hover { color: var(--a-text); }
.iframe-tab.active {
  color: var(--a-teal);
  border-bottom-color: var(--a-teal);
}
.iframe-split {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0;
  height: 520px;
}
.iframe-pane {
  position: relative;
  background: #fff;
  border-right: 1px solid var(--a-border);
}
.iframe-pane:last-child { border-right: none; }
.iframe-pane-label {
  position: absolute;
  top: 8px;
  left: 8px;
  z-index: 2;
  font-family: var(--a-mono);
  font-size: 0.65rem;
  background: rgba(7,7,10,0.85);
  color: var(--a-teal);
  padding: 0.2rem 0.55rem;
  border-radius: 4px;
  border: 1px solid rgba(0,212,170,0.3);
  pointer-events: none;
}
.iframe-pane iframe {
  width: 100%;
  height: 100%;
  border: none;
  display: block;
}
.iframe-placeholder {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  background: var(--a-surface);
  color: var(--a-dim);
  font-family: var(--a-mono);
  font-size: 0.78rem;
  gap: 0.5rem;
  padding: 2rem;
  text-align: center;
}
.iframe-placeholder-icon {
  font-size: 2.5rem;
  opacity: 0.3;
}
.iframe-actions {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.75rem 1rem;
  background: var(--a-surface);
  border-top: 1px solid var(--a-border);
}
.iframe-toggle-btn {
  font-family: var(--a-display);
  font-size: 0.65rem;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  background: var(--a-panel);
  color: var(--a-text);
  border: 1px solid var(--a-border);
  border-radius: 6px;
  padding: 0.35rem 0.85rem;
  cursor: pointer;
  transition: all 0.2s;
  clip-path: polygon(6px 0%, 100% 0%, calc(100% - 6px) 100%, 0% 100%);
}
.iframe-toggle-btn:hover {
  background: var(--a-teal);
  color: #07070a;
  border-color: var(--a-teal);
}

/* ── Screenshot Filmstrip ── */
.filmstrip-wrap {
  background: var(--a-panel);
  border: 1px solid var(--a-border);
  border-radius: 12px;
  overflow: hidden;
  margin-bottom: 1rem;
}
.filmstrip-header {
  padding: 1rem 1.5rem;
  background: var(--a-surface);
  border-bottom: 1px solid var(--a-border);
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.filmstrip-contender-tabs {
  display: flex;
  gap: 0;
  background: var(--a-surface);
  border-bottom: 1px solid var(--a-border);
  padding: 0 1rem;
}
.filmstrip-tab {
  font-family: var(--a-mono);
  font-size: 0.65rem;
  color: var(--a-dim);
  padding: 0.6rem 1rem;
  cursor: pointer;
  border-bottom: 2px solid transparent;
  background: none;
  border-top: none;
  border-left: none;
  border-right: none;
  white-space: nowrap;
  transition: all 0.2s;
}
.filmstrip-tab:hover { color: var(--a-text); }
.filmstrip-tab.active {
  color: var(--a-teal);
  border-bottom-color: var(--a-teal);
}
.filmstrip-scroll {
  display: flex;
  gap: 0.75rem;
  padding: 1rem 1.5rem;
  overflow-x: auto;
  scrollbar-width: thin;
  scrollbar-color: var(--a-border) transparent;
}
.filmstrip-frame {
  flex-shrink: 0;
  cursor: pointer;
  position: relative;
  border-radius: 8px;
  overflow: hidden;
  border: 2px solid var(--a-border);
  transition: all 0.2s;
  background: var(--a-surface);
}
.filmstrip-frame:hover {
  border-color: var(--a-teal);
  box-shadow: 0 0 16px var(--a-teal-glow);
  transform: translateY(-2px);
}
.filmstrip-frame img {
  width: 180px;
  height: 120px;
  object-fit: cover;
  display: block;
}
.filmstrip-frame-label {
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  background: linear-gradient(to top, rgba(7,7,10,0.9), transparent);
  padding: 0.75rem 0.5rem 0.4rem;
  font-family: var(--a-mono);
  font-size: 0.62rem;
  color: var(--a-text);
}
.filmstrip-frame-num {
  position: absolute;
  top: 6px;
  left: 6px;
  background: rgba(7,7,10,0.8);
  color: var(--a-teal);
  font-family: var(--a-mono);
  font-size: 0.6rem;
  padding: 0.15rem 0.4rem;
  border-radius: 3px;
  border: 1px solid rgba(0,212,170,0.3);
}

/* ── Lightbox ── */
#arena-lightbox {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(7,7,10,0.92);
  z-index: 9999;
  align-items: center;
  justify-content: center;
  backdrop-filter: blur(4px);
}
#arena-lightbox.open {
  display: flex;
}
.lightbox-inner {
  position: relative;
  max-width: 92vw;
  max-height: 92vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 1rem;
}
.lightbox-img {
  max-width: 100%;
  max-height: 80vh;
  border-radius: 8px;
  border: 1px solid var(--a-border2);
  box-shadow: 0 0 80px rgba(0,0,0,0.7);
}
.lightbox-caption {
  font-family: var(--a-mono);
  font-size: 0.75rem;
  color: var(--a-dim);
}
.lightbox-close {
  position: absolute;
  top: -40px;
  right: 0;
  background: none;
  border: none;
  color: var(--a-dim);
  font-size: 1.5rem;
  cursor: pointer;
  padding: 0.25rem 0.5rem;
  transition: color 0.2s;
}
.lightbox-close:hover { color: var(--a-text); }
.lightbox-nav {
  position: absolute;
  top: 50%;
  transform: translateY(-50%);
  background: rgba(16,16,22,0.9);
  border: 1px solid var(--a-border);
  border-radius: 8px;
  color: var(--a-text);
  font-size: 1.25rem;
  width: 44px;
  height: 44px;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  transition: all 0.2s;
}
.lightbox-nav:hover {
  border-color: var(--a-teal);
  color: var(--a-teal);
}
.lightbox-prev { left: -56px; }
.lightbox-next { right: -56px; }

/* ── Score Gauges ── */
.score-gauges-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 0.75rem;
  margin-bottom: 1rem;
}
.gauge-card {
  background: var(--a-surface);
  border: 1px solid var(--a-border);
  border-radius: 10px;
  padding: 1rem;
  text-align: center;
  position: relative;
  overflow: hidden;
}
.gauge-card-teal { border-top: 2px solid var(--a-teal); }
.gauge-card-gold { border-top: 2px solid var(--a-gold); }
.gauge-card-red  { border-top: 2px solid var(--a-red); }
.gauge-ring-wrap {
  position: relative;
  width: 80px;
  height: 80px;
  margin: 0 auto 0.6rem;
}
.gauge-ring-svg {
  width: 80px;
  height: 80px;
  transform: rotate(-90deg);
}
.gauge-ring-bg {
  fill: none;
  stroke: var(--a-border);
  stroke-width: 6;
}
.gauge-ring-fill {
  fill: none;
  stroke: var(--a-teal);
  stroke-width: 6;
  stroke-linecap: round;
  stroke-dasharray: 188.5;
  stroke-dashoffset: 188.5;
  animation: ring-fill 1.6s cubic-bezier(0.22,1,0.36,1) forwards;
  animation-delay: 0.4s;
}
.gauge-ring-fill-gold { stroke: var(--a-gold); }
.gauge-ring-fill-red  { stroke: var(--a-red); }
@keyframes ring-fill {
  to { stroke-dashoffset: var(--ring-offset); }
}
.gauge-ring-text {
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: var(--a-display);
  font-size: 1.1rem;
  font-weight: 800;
  color: var(--a-text);
}
.gauge-label {
  font-family: var(--a-mono);
  font-size: 0.65rem;
  color: var(--a-dim);
  text-transform: uppercase;
  letter-spacing: 0.1em;
}
.lh-bar-row {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 0.5rem;
}
.lh-bar-label {
  font-family: var(--a-mono);
  font-size: 0.68rem;
  color: var(--a-dim);
  width: 80px;
  flex-shrink: 0;
}
.lh-bar-track {
  flex: 1;
  height: 8px;
  background: var(--a-border);
  border-radius: 4px;
  overflow: hidden;
}
.lh-bar-fill {
  height: 100%;
  border-radius: 4px;
  animation: bar-fill 1.4s cubic-bezier(0.22,1,0.36,1) forwards;
  animation-delay: 0.5s;
}
.lh-bar-fill-green {
  background: linear-gradient(90deg, #00d4aa, #00ffcc);
  box-shadow: 0 0 6px var(--a-teal-glow);
}
.lh-bar-fill-yellow {
  background: linear-gradient(90deg, #f5c842, #ffd966);
}
.lh-bar-fill-red {
  background: linear-gradient(90deg, #ff2a5f, #ff6688);
}
.lh-bar-val {
  font-family: var(--a-mono);
  font-size: 0.72rem;
  font-weight: 600;
  width: 36px;
  text-align: right;
  flex-shrink: 0;
}

/* ── Hard Gate Grid ── */
.gate-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  gap: 0.5rem;
  margin: 0.75rem 0;
}
.gate-cell {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  background: var(--a-surface);
  border: 1px solid var(--a-border);
  border-radius: 8px;
  padding: 0.5rem 0.75rem;
  font-family: var(--a-mono);
  font-size: 0.7rem;
}
.gate-cell-pass {
  border-color: rgba(0,212,170,0.3);
  background: rgba(0,212,170,0.05);
}
.gate-cell-fail {
  border-color: rgba(255,42,95,0.3);
  background: rgba(255,42,95,0.05);
}
.gate-icon {
  font-size: 1rem;
  flex-shrink: 0;
}
.gate-icon-pass { color: var(--a-teal); text-shadow: 0 0 8px var(--a-teal-glow); }
.gate-icon-fail { color: var(--a-red); text-shadow: 0 0 8px var(--a-red-glow); }

/* ── Heatmap Check Matrix ── */
.heatmap-wrap {
  overflow-x: auto;
  border-radius: 8px;
  border: 1px solid var(--a-border);
}
.heatmap-table {
  width: 100%;
  border-collapse: collapse;
  font-family: var(--a-mono);
  font-size: 0.72rem;
}
.heatmap-table th {
  background: var(--a-surface);
  color: var(--a-dim);
  padding: 0.6rem 1rem;
  text-align: left;
  font-weight: 600;
  letter-spacing: 0.06em;
  border-bottom: 1px solid var(--a-border);
  font-size: 0.65rem;
  text-transform: uppercase;
}
.heatmap-table td {
  padding: 0.5rem 0.75rem;
  border-bottom: 1px solid var(--a-border);
  border-right: 1px solid var(--a-border);
  text-align: center;
}
.heatmap-table td:first-child {
  text-align: left;
  color: var(--a-dim);
}
.heatmap-table tr:last-child td { border-bottom: none; }
.heatmap-table td:last-child { border-right: none; }
.heatmap-cell-pass {
  background: rgba(0,212,170,0.12);
  color: var(--a-teal);
  font-weight: 700;
  border-radius: 4px;
  padding: 0.3rem 0.6rem;
  display: inline-block;
  cursor: default;
  transition: all 0.15s;
  font-size: 0.65rem;
  letter-spacing: 0.08em;
  box-shadow: inset 0 0 0 1px rgba(0,212,170,0.3);
}
.heatmap-cell-pass:hover {
  background: rgba(0,212,170,0.25);
  box-shadow: 0 0 12px var(--a-teal-glow), inset 0 0 0 1px rgba(0,212,170,0.5);
}
.heatmap-cell-fail {
  background: rgba(255,42,95,0.12);
  color: var(--a-red);
  font-weight: 700;
  border-radius: 4px;
  padding: 0.3rem 0.6rem;
  display: inline-block;
  cursor: default;
  transition: all 0.15s;
  font-size: 0.65rem;
  letter-spacing: 0.08em;
  box-shadow: inset 0 0 0 1px rgba(255,42,95,0.3);
}
.heatmap-cell-fail:hover {
  background: rgba(255,42,95,0.25);
  box-shadow: 0 0 12px var(--a-red-glow), inset 0 0 0 1px rgba(255,42,95,0.5);
}
.heatmap-row-alt { background: rgba(255,255,255,0.015); }

/* ── Animated Score Counter ── */
.overall-score-banner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 2rem;
  background: var(--a-surface);
  border: 1px solid var(--a-border);
  border-radius: 10px;
  padding: 1rem 1.5rem;
  margin-bottom: 0.75rem;
}
.overall-score-name {
  font-family: var(--a-display);
  font-size: 0.85rem;
  font-weight: 700;
  color: var(--a-text);
}
.overall-score-sub {
  font-family: var(--a-mono);
  font-size: 0.65rem;
  color: var(--a-dim);
}
.overall-score-val {
  font-family: var(--a-display);
  font-size: 2.5rem;
  font-weight: 800;
  animation: score-reveal 1s ease both;
}
.overall-score-val-winner {
  color: var(--a-teal);
  text-shadow: 0 0 30px var(--a-teal-glow);
}
.overall-score-val-loser { color: var(--a-dim); }
.overall-score-val-fail  { color: var(--a-red); }

/* ── Clip-path buttons ── */
.arena-btn {
  font-family: var(--a-display);
  font-size: 0.65rem;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  background: var(--a-panel);
  color: var(--a-teal);
  border: 1px solid rgba(0,212,170,0.4);
  border-radius: 4px;
  padding: 0.35rem 0.85rem;
  cursor: pointer;
  transition: all 0.2s;
  clip-path: polygon(8px 0%, 100% 0%, calc(100% - 8px) 100%, 0% 100%);
}
.arena-btn:hover {
  background: var(--a-teal);
  color: #07070a;
}
.arena-copy-btn {
  background: transparent;
  border: 1px solid var(--a-border);
  color: var(--a-dim);
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.7rem;
  font-family: var(--a-mono);
  transition: all 0.2s;
}
.arena-copy-btn:hover {
  border-color: var(--a-teal);
  color: var(--a-teal);
}

/* ── Metric chips (new style) ── */
.a-diag-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 0.4rem;
}
.a-diag-chip {
  background: var(--a-surface);
  border: 1px solid var(--a-border);
  border-radius: 8px;
  padding: 0.45rem 0.6rem;
}
.a-chip-label {
  font-family: var(--a-mono);
  font-size: 0.62rem;
  color: var(--a-dim);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 0.15rem;
}
.a-chip-val {
  font-family: var(--a-mono);
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--a-text);
}

/* ── Utility ── */
.a-section-gap { margin-bottom: 2rem; }
.a-label {
  font-family: var(--a-display);
  font-size: 0.62rem;
  font-weight: 700;
  letter-spacing: 0.15em;
  text-transform: uppercase;
  color: var(--a-teal);
  margin-bottom: 0.4rem;
  padding-left: 0.75rem;
  border-left: 2px solid var(--a-teal);
  box-shadow: -4px 0 8px var(--a-teal-glow2);
}
.a-dim   { color: var(--a-dim); }
.a-mono  { font-family: var(--a-mono); font-size: 0.85rem; }
.a-title {
  font-family: var(--a-display);
  font-size: 1.4rem;
  font-weight: 800;
  color: var(--a-text);
  margin-bottom: 0.25rem;
}
.a-subtitle {
  font-family: var(--a-body);
  font-size: 0.88rem;
  color: var(--a-dim);
  margin-bottom: 1.5rem;
}

@media (max-width: 700px) {
  .vs-grid {
    grid-template-columns: 1fr;
  }
  .vs-divider {
    width: 100%;
    flex-direction: row;
    padding: 0.5rem 0;
  }
  .vs-badge::before, .vs-badge::after { display: none; }
  .iframe-split { grid-template-columns: 1fr; height: auto; }
  .iframe-pane { height: 300px; }
  .lightbox-prev { left: -44px; }
  .lightbox-next { right: -44px; }
}
</style>`;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function renderMetricCell(label: string, value: string): string {
  return `
    <div class="a-diag-chip">
      <div class="a-chip-label">${esc(label)}</div>
      <div class="a-chip-val">${esc(value)}</div>
    </div>
  `;
}

function lhColor(v: number): string {
  if (v >= 0.9) return 'green';
  if (v >= 0.5) return 'yellow';
  return 'red';
}

// ─── VS Hero Screen ─────────────────────────────────────────────────────────

function vsHeroSection(report: ArenaReportView): string {
  const winner = report.winner.contender_id;
  const maxScore = Math.max(...report.contenders.map((c) => c.score), 1);

  // Pick 2 featured contenders for the main VS screen
  const featured = report.contenders.slice(0, 2);
  const rest     = report.contenders.slice(2);

  const featuredCols = featured.map((c, idx) => {
    const isWinner = c.contender_id === winner;
    const isFail   = !c.hard_gate_pass;
    const barPct   = Math.round((c.score / maxScore) * 100);

    const colClass = isWinner ? 'vs-col vs-col-winner' : isFail ? 'vs-col vs-col-loser vs-col-fail' : 'vs-col vs-col-loser';
    const scoreClass = isWinner ? 'vs-score-num' : isFail ? 'vs-score-num vs-score-num-fail' : 'vs-score-num vs-score-num-loser';
    const barClass = isWinner ? 'vs-score-bar-fill' : isFail ? 'vs-score-bar-fill vs-score-bar-fill-fail' : 'vs-score-bar-fill vs-score-bar-fill-loser';
    const gateClass = c.hard_gate_pass ? 'vs-gate vs-gate-pass' : 'vs-gate vs-gate-fail';
    const gateIcon = c.hard_gate_pass ? '✓' : '✗';

    const crown = isWinner ? `<div class="vs-crown">👑 Winner</div>` : '';

    const evLinks = c.score_explain.evidence_links.slice(0, 3).map((ev) =>
      `<a href="${esc(ev.url)}" target="_blank" rel="noreferrer" class="vs-ev-link">${esc(ev.label)} ↗</a>`
    ).join('');

    // Animation delay for second column
    const delay = idx === 1 ? 'animation-delay: 0.25s;' : '';

    return `
      <div class="${colClass}" style="${delay}">
        ${crown}
        <div>
          <div class="vs-model-name">${esc(c.model)}</div>
          <div class="vs-harness">${esc(c.harness)}</div>
        </div>
        <div class="vs-score-wrap">
          <div class="vs-score-label">Score</div>
          <div class="${scoreClass}" style="${delay}">${c.score.toFixed(1)}</div>
          <div class="vs-score-bar-track">
            <div class="${barClass}" style="width:${barPct}%"></div>
          </div>
        </div>
        <div style="display:flex; align-items:center; gap:0.5rem; flex-wrap:wrap">
          <span class="${gateClass}">${gateIcon} ${c.hard_gate_pass ? 'Gate Pass' : 'Gate Fail'}</span>
          <span style="font-family:var(--a-mono); font-size:0.65rem; color:var(--a-dim)">${esc(c.contender_id)}</span>
        </div>
        <div class="vs-metrics-row">
          <div class="vs-metric-chip">
            <div class="vs-metric-label">Quality</div>
            <div class="vs-metric-val">${c.metrics.quality_score.toFixed(0)}</div>
          </div>
          <div class="vs-metric-chip">
            <div class="vs-metric-label">Efficiency</div>
            <div class="vs-metric-val">${c.metrics.efficiency_score.toFixed(0)}</div>
          </div>
          <div class="vs-metric-chip">
            <div class="vs-metric-label">Cost</div>
            <div class="vs-metric-val">$${c.metrics.cost_usd.toFixed(3)}</div>
          </div>
          <div class="vs-metric-chip">
            <div class="vs-metric-label">Latency</div>
            <div class="vs-metric-val">${(c.metrics.latency_ms / 1000).toFixed(1)}s</div>
          </div>
        </div>
        ${evLinks ? `<div class="vs-evidence-links">${evLinks}</div>` : ''}
      </div>
    `;
  }).join('');

  const restCards = rest.map((c) => {
    const isWinner = c.contender_id === winner;
    const scoreClass = isWinner ? 'vs-more-score' : 'vs-more-score';
    const tint = isWinner ? ' style="color:var(--a-teal)"' : (!c.hard_gate_pass ? ' style="color:var(--a-red)"' : '');

    return `
      <div class="vs-more-card">
        <div class="${scoreClass}"${tint}>${c.score.toFixed(1)}</div>
        <div>
          <div style="font-family:var(--a-display); font-size:0.88rem; font-weight:700; color:var(--a-text)">${esc(c.model)}</div>
          <div style="font-family:var(--a-mono); font-size:0.65rem; color:var(--a-dim)">${esc(c.contender_id)}</div>
          <div style="margin-top:0.35rem; font-family:var(--a-mono); font-size:0.65rem; color:var(--a-dim)">${esc(c.harness)}</div>
        </div>
      </div>
    `;
  }).join('');

  return `
    <div class="arena-hero-wrap arena-noise">
      <div class="arena-hero-title">⚔ Arena Compare · ${esc(report.arena_id)}</div>
      <div class="vs-grid">
        ${featuredCols.length > 0 ? featuredCols[0] : ''}
        <div class="vs-divider">
          <div class="vs-badge">VS</div>
        </div>
        ${featuredCols.length > 1 ? featuredCols[1] : '<div class="vs-col" style="align-items:center;justify-content:center;color:var(--a-dim)">—</div>'}
      </div>
      ${rest.length > 0 ? `<div class="vs-more-strip">${restCards}</div>` : ''}
    </div>
  `;
}

// ─── Live Output Iframe Viewer ───────────────────────────────────────────────

function iframeOutputViewer(report: ArenaReportView, artifactsBaseUrl: string | null): string {
  if (!artifactsBaseUrl || !report.contract?.bounty_id) {
    return `
      <div class="arena-card a-section-gap">
        <div class="a-label">Live Output Viewer</div>
        <div style="height:200px; display:flex; align-items:center; justify-content:center; flex-direction:column; gap:0.75rem">
          <div style="font-size:2.5rem; opacity:0.2">⬛</div>
          <div style="font-family:var(--a-mono); font-size:0.78rem; color:var(--a-dim)">
            No artifactsBaseUrl configured — set it to enable split-screen output viewer
          </div>
        </div>
      </div>
    `;
  }

  const bountyId = esc(report.contract.bounty_id);

  const tabs = report.contenders.map((c, idx) => {
    const active = idx === 0 ? ' active' : '';
    return `<button class="iframe-tab${active}" onclick="arenaIframeTab(${idx})" type="button">${esc(c.contender_id)}</button>`;
  }).join('');

  // Build iframe pairs
  const pairs: string[] = [];
  for (let i = 0; i < report.contenders.length; i += 2) {
    const a = report.contenders[i];
    const b = report.contenders[i + 1];
    const display = i === 0 ? '' : ' style="display:none"';
    const urlA = `${esc(artifactsBaseUrl)}/arena/${bountyId}/${esc(a.contender_id)}/output/index.html`;
    const urlB = b ? `${esc(artifactsBaseUrl)}/arena/${bountyId}/${esc(b.contender_id)}/output/index.html` : null;

    const paneB = urlB
      ? `<div class="iframe-pane">
           <div class="iframe-pane-label">${esc(b.contender_id)}</div>
           <iframe src="${urlB}" sandbox="allow-scripts allow-same-origin" loading="lazy" title="${esc(b.contender_id)} output"></iframe>
         </div>`
      : `<div class="iframe-pane"><div class="iframe-placeholder"><div class="iframe-placeholder-icon">□</div><span>No second contender</span></div></div>`;

    pairs.push(`
      <div class="iframe-split"${display} data-pair="${i}">
        <div class="iframe-pane">
          <div class="iframe-pane-label">${esc(a.contender_id)}</div>
          <iframe src="${urlA}" sandbox="allow-scripts allow-same-origin" loading="lazy" title="${esc(a.contender_id)} output"></iframe>
        </div>
        ${paneB}
      </div>
    `);
  }

  return `
    <div class="iframe-viewer a-section-gap" id="live-output">
      <div class="iframe-tab-bar">
        <div style="font-family:var(--a-display); font-size:0.65rem; font-weight:700; letter-spacing:0.15em; text-transform:uppercase; color:var(--a-teal); padding:0.75rem 0.75rem 0.75rem 0; display:flex; align-items:center; gap:0.5rem; flex-shrink:0; border-right:1px solid var(--a-border); margin-right:0.75rem; padding-right:0.75rem;">
          ▶ Live Output
        </div>
        ${tabs}
      </div>
      <div id="iframe-pairs">
        ${pairs.join('')}
      </div>
      <div class="iframe-actions">
        <button class="iframe-toggle-btn" onclick="arenaIframeFullscreen()" type="button">⤢ Full Screen</button>
        <span style="font-family:var(--a-mono); font-size:0.65rem; color:var(--a-dim)">Split-screen · sandboxed iframes</span>
      </div>
    </div>
    <script>
    (function() {
      function arenaIframeTab(idx) {
        var pairs = document.querySelectorAll('#iframe-pairs .iframe-split');
        var tabs  = document.querySelectorAll('.iframe-tab');
        pairs.forEach(function(p, i) { p.style.display = i === Math.floor(idx / 2) * 2 / 2 ? '' : 'none'; });
        tabs.forEach(function(t, i)  { t.classList.toggle('active', i === idx); });
      }
      function arenaIframeFullscreen() {
        var el = document.getElementById('live-output');
        if (el) {
          if (document.fullscreenElement) {
            document.exitFullscreen();
          } else {
            el.requestFullscreen && el.requestFullscreen();
          }
        }
      }
      window.arenaIframeTab = arenaIframeTab;
      window.arenaIframeFullscreen = arenaIframeFullscreen;
    })();
    </script>
  `;
}

// ─── Screenshot Filmstrip ────────────────────────────────────────────────────

function screenshotFilmstrip(report: ArenaReportView, artifactsBaseUrl: string | null): string {
  if (!artifactsBaseUrl || !report.contract?.bounty_id) return '';

  const bountyId = esc(report.contract.bounty_id);
  const steps = [
    { file: '01-browse.png',  label: 'Browse' },
    { file: '02-details.png', label: 'Details' },
    { file: '03-claim.png',   label: 'Claim' },
    { file: '04-submit.png',  label: 'Submit' },
  ];

  const contenderTabs = report.contenders.map((c, idx) => {
    const active = idx === 0 ? ' active' : '';
    return `<button class="filmstrip-tab${active}" onclick="arenaFilmTab(${idx})" type="button">${esc(c.contender_id)}</button>`;
  }).join('');

  const contenderStrips = report.contenders.map((c, cIdx) => {
    const display = cIdx === 0 ? '' : ' style="display:none"';
    const frames = steps.map((step, sIdx) => {
      const url = `${esc(artifactsBaseUrl)}/arena/${bountyId}/${esc(c.contender_id)}/journey/screenshots/${esc(step.file)}`;
      const imgIdx = cIdx * steps.length + sIdx;
      return `
        <div class="filmstrip-frame" onclick="arenaLightbox(${imgIdx})" title="${esc(step.label)}">
          <div class="filmstrip-frame-num">${String(sIdx + 1).padStart(2, '0')}</div>
          <img src="${url}" alt="${esc(step.label)} — ${esc(c.contender_id)}" loading="lazy"
               onerror="this.parentElement.style.opacity='0.3'; this.style.display='none'; this.parentElement.querySelector('.filmstrip-frame-label').textContent='Not available';">
          <div class="filmstrip-frame-label">${esc(step.label)}</div>
        </div>
      `;
    }).join('');

    return `<div class="filmstrip-scroll" data-filmstrip="${cIdx}"${display}>${frames}</div>`;
  }).join('');

  // Build flat image list for lightbox
  const allImages: string[] = [];
  const allCaptions: string[] = [];
  for (const c of report.contenders) {
    for (const step of steps) {
      allImages.push(`${artifactsBaseUrl}/arena/${bountyId}/${c.contender_id}/journey/screenshots/${step.file}`);
      allCaptions.push(`${c.contender_id} — ${step.label}`);
    }
  }

  const imagesJson = JSON.stringify(allImages.map((u) => esc(u)));
  const captionsJson = JSON.stringify(allCaptions.map((cap) => esc(cap)));

  return `
    <div class="filmstrip-wrap a-section-gap" id="screenshots">
      <div class="filmstrip-header">
        <div class="a-label" style="margin-bottom:0">Screenshot Journey</div>
        <span style="font-family:var(--a-mono); font-size:0.65rem; color:var(--a-dim)">Click to expand · arrow keys to navigate</span>
      </div>
      <div class="filmstrip-contender-tabs">
        ${contenderTabs}
      </div>
      ${contenderStrips}
    </div>

    <div id="arena-lightbox">
      <div class="lightbox-inner">
        <button class="lightbox-close" onclick="arenaCloseLightbox()" type="button">✕</button>
        <button class="lightbox-nav lightbox-prev" onclick="arenaLightboxNav(-1)" type="button">‹</button>
        <img id="lightbox-img" class="lightbox-img" src="" alt="">
        <button class="lightbox-nav lightbox-next" onclick="arenaLightboxNav(1)" type="button">›</button>
        <div id="lightbox-caption" class="lightbox-caption"></div>
      </div>
    </div>

    <script>
    (function() {
      var _imgs = ${imagesJson};
      var _caps = ${captionsJson};
      var _cur = 0;

      function arenaFilmTab(idx) {
        var strips = document.querySelectorAll('[data-filmstrip]');
        var tabs   = document.querySelectorAll('.filmstrip-tab');
        strips.forEach(function(s, i) { s.style.display = i === idx ? '' : 'none'; });
        tabs.forEach(function(t, i)   { t.classList.toggle('active', i === idx); });
      }

      function arenaLightbox(idx) {
        _cur = idx;
        document.getElementById('lightbox-img').src = _imgs[idx] || '';
        document.getElementById('lightbox-caption').textContent = _caps[idx] || '';
        document.getElementById('arena-lightbox').classList.add('open');
      }

      function arenaCloseLightbox() {
        document.getElementById('arena-lightbox').classList.remove('open');
      }

      function arenaLightboxNav(dir) {
        _cur = (_cur + dir + _imgs.length) % _imgs.length;
        document.getElementById('lightbox-img').src = _imgs[_cur] || '';
        document.getElementById('lightbox-caption').textContent = _caps[_cur] || '';
      }

      document.addEventListener('keydown', function(e) {
        if (!document.getElementById('arena-lightbox').classList.contains('open')) return;
        if (e.key === 'ArrowLeft')  arenaLightboxNav(-1);
        if (e.key === 'ArrowRight') arenaLightboxNav(1);
        if (e.key === 'Escape')     arenaCloseLightbox();
      });
      document.getElementById('arena-lightbox').addEventListener('click', function(e) {
        if (e.target === this) arenaCloseLightbox();
      });

      window.arenaFilmTab    = arenaFilmTab;
      window.arenaLightbox   = arenaLightbox;
      window.arenaCloseLightbox  = arenaCloseLightbox;
      window.arenaLightboxNav    = arenaLightboxNav;
    })();
    </script>
  `;
}

// ─── Score Breakdown Gauges ──────────────────────────────────────────────────

function gaugeRing(value: number, max: number, label: string, colorClass: string, delay: number): string {
  const pct   = Math.min(1, Math.max(0, value / max));
  const circ  = 188.5;
  const offset = circ - pct * circ;
  const display = max === 100 ? value.toFixed(0) : value.toFixed(1);
  return `
    <div class="gauge-card gauge-card-${colorClass}">
      <div class="gauge-ring-wrap">
        <svg class="gauge-ring-svg" viewBox="0 0 68 68">
          <circle class="gauge-ring-bg" cx="34" cy="34" r="30"/>
          <circle class="gauge-ring-fill gauge-ring-fill-${colorClass}"
                  cx="34" cy="34" r="30"
                  style="--ring-offset:${offset}; animation-delay:${delay}s"
                  stroke-dashoffset="${circ}"/>
        </svg>
        <div class="gauge-ring-text">${display}</div>
      </div>
      <div class="gauge-label">${esc(label)}</div>
    </div>
  `;
}

function renderEvaluatorGauges(raw: Record<string, unknown>): string {
  const ux     = typeof raw.ux_score     === 'number' ? raw.ux_score     : null;
  const perf   = typeof raw.perf_score   === 'number' ? raw.perf_score   : null;
  const a11y   = typeof raw.a11y_score   === 'number' ? raw.a11y_score   : null;
  const visual = typeof raw.visual_score === 'number' ? raw.visual_score : null;
  const maint  = typeof raw.maint_score  === 'number' ? raw.maint_score  : null;
  const lhPerf = typeof raw.lighthouse_performance  === 'number' ? raw.lighthouse_performance  : null;
  const lhA11y = typeof raw.lighthouse_accessibility === 'number' ? raw.lighthouse_accessibility : null;
  const lhCls  = typeof raw.lighthouse_cls           === 'number' ? raw.lighthouse_cls           : null;
  const flowRate     = typeof raw.flow_success_rate    === 'number' ? raw.flow_success_rate    : null;
  const avgTiming    = typeof raw.avg_timing_ms        === 'number' ? raw.avg_timing_ms        : null;
  const runtimeErr   = typeof raw.runtime_error_count  === 'number' ? raw.runtime_error_count  : null;
  const critA11y     = typeof raw.critical_a11y_violations === 'number' ? raw.critical_a11y_violations : null;
  const friction     = typeof raw.friction_events      === 'number' ? raw.friction_events      : null;

  const gauges: string[] = [];
  let d = 0.4;
  if (ux     !== null) { gauges.push(gaugeRing(ux,     100, 'UX',     'teal', d)); d += 0.1; }
  if (perf   !== null) { gauges.push(gaugeRing(perf,   100, 'Perf',   'teal', d)); d += 0.1; }
  if (a11y   !== null) { gauges.push(gaugeRing(a11y,   100, 'A11y',   'teal', d)); d += 0.1; }
  if (visual !== null) { gauges.push(gaugeRing(visual, 100, 'Visual', 'gold', d)); d += 0.1; }
  if (maint  !== null) { gauges.push(gaugeRing(maint,  100, 'Maint',  'gold', d)); d += 0.1; }

  // Hard gates display
  const hardGates = raw.hard_gates;
  const hg = hardGates && typeof hardGates === 'object' ? hardGates as Record<string, unknown> : {};
  const gateItems: Array<{ label: string; pass: boolean }> = [];
  if (typeof hg.core_flows_pass   === 'boolean') gateItems.push({ label: 'Core Flows',    pass: hg.core_flows_pass });
  if (typeof hg.no_runtime_errors === 'boolean') gateItems.push({ label: 'No RT Errors',  pass: hg.no_runtime_errors });
  if (typeof hg.no_a11y_critical  === 'boolean') gateItems.push({ label: 'No Crit A11y',  pass: hg.no_a11y_critical });

  const lhBars: string[] = [];
  if (lhPerf !== null) {
    const pct = (lhPerf * 100).toFixed(0);
    const col = lhColor(lhPerf);
    lhBars.push(`
      <div class="lh-bar-row">
        <div class="lh-bar-label">LH Perf</div>
        <div class="lh-bar-track"><div class="lh-bar-fill lh-bar-fill-${col}" style="width:${pct}%"></div></div>
        <div class="lh-bar-val" style="color:${col === 'green' ? 'var(--a-teal)' : col === 'yellow' ? 'var(--a-gold)' : 'var(--a-red)'}">${pct}%</div>
      </div>
    `);
  }
  if (lhA11y !== null) {
    const pct = (lhA11y * 100).toFixed(0);
    const col = lhColor(lhA11y);
    lhBars.push(`
      <div class="lh-bar-row">
        <div class="lh-bar-label">LH A11y</div>
        <div class="lh-bar-track"><div class="lh-bar-fill lh-bar-fill-${col}" style="width:${pct}%"></div></div>
        <div class="lh-bar-val" style="color:${col === 'green' ? 'var(--a-teal)' : col === 'yellow' ? 'var(--a-gold)' : 'var(--a-red)'}">${pct}%</div>
      </div>
    `);
  }
  if (lhCls !== null) {
    lhBars.push(`
      <div class="lh-bar-row">
        <div class="lh-bar-label">LH CLS</div>
        <div class="lh-bar-track"><div class="lh-bar-fill lh-bar-fill-${lhCls <= 0.1 ? 'green' : lhCls <= 0.25 ? 'yellow' : 'red'}" style="width:${Math.max(4, 100 - lhCls * 400).toFixed(0)}%"></div></div>
        <div class="lh-bar-val">${lhCls.toFixed(3)}</div>
      </div>
    `);
  }

  const extraChips: string[] = [];
  if (flowRate  !== null) extraChips.push(renderMetricCell('Flow rate',  (flowRate * 100).toFixed(0) + '%'));
  if (avgTiming !== null) extraChips.push(renderMetricCell('Avg timing', avgTiming.toFixed(0) + 'ms'));
  if (runtimeErr !== null) extraChips.push(renderMetricCell('RT errors', String(runtimeErr)));
  if (critA11y   !== null) extraChips.push(renderMetricCell('Crit A11y', String(critA11y)));
  if (friction   !== null) extraChips.push(renderMetricCell('Friction',  String(friction)));

  const evalReasonCodes = Array.isArray(raw.reason_codes) ? raw.reason_codes as string[] : [];

  return `
    ${gauges.length > 0 ? `<div class="score-gauges-grid">${gauges.join('')}</div>` : ''}
    ${lhBars.length > 0 ? `<div style="margin-bottom:0.75rem">${lhBars.join('')}</div>` : ''}
    ${gateItems.length > 0 ? `
      <div class="gate-grid">
        ${gateItems.map((g) => `
          <div class="gate-cell ${g.pass ? 'gate-cell-pass' : 'gate-cell-fail'}">
            <span class="gate-icon ${g.pass ? 'gate-icon-pass' : 'gate-icon-fail'}">${g.pass ? '✓' : '✗'}</span>
            <span>${esc(g.label)}</span>
          </div>
        `).join('')}
      </div>
    ` : ''}
    ${extraChips.length > 0 ? `<div class="a-diag-grid" style="margin-top:0.5rem">${extraChips.join('')}</div>` : ''}
    ${evalReasonCodes.length > 0 ? `<div style="margin-top:0.5rem; font-family:var(--a-mono); font-size:0.65rem; color:var(--a-dim)">${evalReasonCodes.map((rc) => esc(rc)).join(', ')}</div>` : ''}
  `;
}

function renderCanonicalGauges(contender: ArenaContenderView): string {
  const q = contender.metrics.quality_score;
  const e = contender.metrics.efficiency_score;
  const r = contender.metrics.risk_score;
  return `
    <div class="score-gauges-grid">
      ${gaugeRing(q, 100, 'Quality',    'teal', 0.4)}
      ${gaugeRing(e, 100, 'Efficiency', 'gold', 0.5)}
      ${gaugeRing(Math.max(0, 100 - r), 100, 'Safety', r > 60 ? 'red' : 'teal', 0.6)}
    </div>
    <div class="a-diag-grid">
      ${renderMetricCell('quality',    q.toFixed(1))}
      ${renderMetricCell('risk',       contender.metrics.risk_score.toFixed(1))}
      ${renderMetricCell('efficiency', e.toFixed(1))}
      ${renderMetricCell('cost',       '$' + contender.metrics.cost_usd.toFixed(4))}
    </div>
  `;
}

function scoreBreakdownSection(report: ArenaReportView): string {
  const banners = report.contenders.map((c) => {
    const isWinner = c.contender_id === report.winner.contender_id;
    const isFail   = !c.hard_gate_pass;
    const valClass = isWinner ? 'overall-score-val-winner' : isFail ? 'overall-score-val-fail' : 'overall-score-val-loser';
    const hasEval = c.raw_evaluator_metrics !== null && typeof c.raw_evaluator_metrics === 'object'
      && Object.keys(c.raw_evaluator_metrics).length > 0;

    const gaugesHtml = hasEval
      ? renderEvaluatorGauges(c.raw_evaluator_metrics!)
      : renderCanonicalGauges(c);

    const evLinks = c.score_explain.evidence_links.map((ev) =>
      `<a href="${esc(ev.url)}" target="_blank" rel="noreferrer" class="vs-ev-link">${esc(ev.label)} ↗</a>`
    ).join('');

    return `
      <div class="arena-card ${isWinner ? 'arena-card-accent-teal' : isFail ? 'arena-card-accent-red' : ''}">
        <div class="overall-score-banner">
          <div>
            <div class="overall-score-name">${esc(c.model)}</div>
            <div class="overall-score-sub">${esc(c.contender_id)} · ${esc(c.harness)}</div>
          </div>
          <div class="overall-score-val ${valClass}">${c.score.toFixed(1)}</div>
        </div>
        ${gaugesHtml}
        ${evLinks ? `<div class="vs-evidence-links" style="margin-top:0.6rem">${evLinks}</div>` : ''}
      </div>
    `;
  }).join('');

  return `
    <div class="a-section-gap" id="scores">
      <div class="a-label">Score Breakdown</div>
      ${banners}
    </div>
  `;
}

// ─── Contract Check Matrix (heatmap) ────────────────────────────────────────

function contractCheckMatrix(report: ArenaReportView): string {
  const criterionIds = [...new Set(
    report.contenders.flatMap((c) => c.check_results.map((ch) => ch.criterion_id))
  )].sort((a, b) => a.localeCompare(b));

  if (criterionIds.length === 0) {
    return `
      <div style="font-family:var(--a-mono); font-size:0.82rem; color:var(--a-dim); padding:1rem">
        No per-criterion check results provided.
      </div>
    `;
  }

  const headerCells = report.contenders.map((c) => {
    const isWinner = c.contender_id === report.winner.contender_id;
    return `<th style="${isWinner ? 'color:var(--a-teal)' : ''}">${esc(c.contender_id)}</th>`;
  }).join('');

  const rows = criterionIds.map((criterionId, rowIdx) => {
    const cells = report.contenders.map((c) => {
      const ch = c.check_results.find((entry) => entry.criterion_id === criterionId);
      if (!ch) return `<td><span style="color:var(--a-dim); font-size:0.65rem">N/A</span></td>`;
      const cls = ch.status === 'PASS' ? 'heatmap-cell-pass' : 'heatmap-cell-fail';
      return `<td><span class="${cls}" title="${esc(ch.reason_code)}">${esc(ch.status)}</span></td>`;
    }).join('');
    const rowAlt = rowIdx % 2 === 1 ? ' class="heatmap-row-alt"' : '';
    return `<tr${rowAlt}><td><span style="font-family:var(--a-mono); font-size:0.72rem">${esc(criterionId)}</span></td>${cells}</tr>`;
  }).join('');

  return `
    <div class="heatmap-wrap">
      <table class="heatmap-table">
        <thead>
          <tr>
            <th style="text-align:left">Contract Criterion</th>
            ${headerCells}
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

// ─── Metric Cell (classic) for non-gauge sections ────────────────────────────

function renderMetricCellOld(label: string, value: string): string {
  return `
    <div class="a-diag-chip">
      <div class="a-chip-label">${esc(label)}</div>
      <div class="a-chip-val">${esc(value)}</div>
    </div>
  `;
}

// ─── Contenders table (full data, required by tests) ─────────────────────────

function renderReviewPasteInline(paste: string): string {
  if (!paste || paste.length === 0) return '<span style="color:var(--a-dim); font-size:0.75rem">No review paste</span>';
  const lines = paste.split('\n').map((line) => esc(line.trim())).filter((l) => l.length > 0);
  return `
    <div style="font-size:0.75rem; line-height:1.4; font-family:var(--a-mono); background:var(--a-surface); border:1px solid var(--a-border); border-radius:6px; padding:0.5rem; max-height:6rem; overflow-y:auto; white-space:pre-wrap">${lines.join('\n')}</div>
  `;
}

function renderEvaluatorMetrics(raw: Record<string, unknown>): string {
  const ux     = typeof raw.ux_score     === 'number' ? raw.ux_score     : null;
  const perf   = typeof raw.perf_score   === 'number' ? raw.perf_score   : null;
  const a11y   = typeof raw.a11y_score   === 'number' ? raw.a11y_score   : null;
  const visual = typeof raw.visual_score === 'number' ? raw.visual_score : null;
  const maint  = typeof raw.maint_score  === 'number' ? raw.maint_score  : null;
  const lhPerf = typeof raw.lighthouse_performance  === 'number' ? raw.lighthouse_performance  : null;
  const lhA11y = typeof raw.lighthouse_accessibility === 'number' ? raw.lighthouse_accessibility : null;
  const lhCls  = typeof raw.lighthouse_cls           === 'number' ? raw.lighthouse_cls           : null;
  const flowRate   = typeof raw.flow_success_rate    === 'number' ? raw.flow_success_rate    : null;
  const flowsPassed = typeof raw.flows_passed        === 'number' ? raw.flows_passed         : null;
  const flowsTotal  = typeof raw.flows_total         === 'number' ? raw.flows_total          : null;
  const avgTiming  = typeof raw.avg_timing_ms        === 'number' ? raw.avg_timing_ms        : null;
  const rtErr      = typeof raw.runtime_error_count  === 'number' ? raw.runtime_error_count  : null;
  const critA11y   = typeof raw.critical_a11y_violations === 'number' ? raw.critical_a11y_violations : null;
  const friction   = typeof raw.friction_events      === 'number' ? raw.friction_events      : null;

  const cells: string[] = [];
  if (ux     !== null) cells.push(renderMetricCellOld('UX',      ux.toFixed(1)));
  if (perf   !== null) cells.push(renderMetricCellOld('perf',    perf.toFixed(1)));
  if (a11y   !== null) cells.push(renderMetricCellOld('a11y',    a11y.toFixed(1)));
  if (visual !== null) cells.push(renderMetricCellOld('visual',  visual.toFixed(1)));
  if (maint  !== null) cells.push(renderMetricCellOld('maint',   maint.toFixed(1)));
  if (lhPerf !== null) cells.push(renderMetricCellOld('LH perf', (lhPerf * 100).toFixed(0) + '%'));
  if (lhA11y !== null) cells.push(renderMetricCellOld('LH a11y', (lhA11y * 100).toFixed(0) + '%'));
  if (lhCls  !== null) cells.push(renderMetricCellOld('CLS',     lhCls.toFixed(3)));
  if (flowRate  !== null) cells.push(renderMetricCellOld('flows',     (flowRate * 100).toFixed(0) + '%'));
  if (flowsPassed !== null && flowsTotal !== null) cells.push(renderMetricCellOld('flow pass', flowsPassed + '/' + flowsTotal));
  if (avgTiming !== null) cells.push(renderMetricCellOld('avg timing', avgTiming.toFixed(0) + 'ms'));
  if (rtErr     !== null) cells.push(renderMetricCellOld('RT errors',  String(rtErr)));
  if (critA11y  !== null) cells.push(renderMetricCellOld('crit a11y',  String(critA11y)));
  if (friction  !== null) cells.push(renderMetricCellOld('friction',   String(friction)));

  const hg = raw.hard_gates && typeof raw.hard_gates === 'object' ? raw.hard_gates as Record<string, unknown> : {};
  if (typeof hg.core_flows_pass   === 'boolean') cells.push(renderMetricCellOld('core flows',   hg.core_flows_pass   ? 'PASS' : 'FAIL'));
  if (typeof hg.no_runtime_errors === 'boolean') cells.push(renderMetricCellOld('no RT err',    hg.no_runtime_errors ? 'PASS' : 'FAIL'));
  if (typeof hg.no_a11y_critical  === 'boolean') cells.push(renderMetricCellOld('no crit a11y', hg.no_a11y_critical  ? 'PASS' : 'FAIL'));

  const evalRc = Array.isArray(raw.reason_codes) ? raw.reason_codes as string[] : [];
  if (cells.length === 0) return '';
  return `
    <div class="a-diag-grid" style="grid-template-columns: repeat(3, minmax(90px, 1fr)); gap:0.25rem">
      ${cells.join('')}
    </div>
    ${evalRc.length > 0 ? `<div style="font-family:var(--a-mono); font-size:0.65rem; color:var(--a-dim); margin-top:0.25rem">${evalRc.map((rc) => esc(rc)).join(', ')}</div>` : ''}
  `;
}

function renderCanonicalMetrics(c: ArenaContenderView): string {
  return `
    <div class="a-diag-grid" style="grid-template-columns: repeat(2, minmax(100px, 1fr)); gap:0.3rem">
      ${renderMetricCellOld('quality',    c.metrics.quality_score.toFixed(2))}
      ${renderMetricCellOld('risk',       c.metrics.risk_score.toFixed(2))}
      ${renderMetricCellOld('efficiency', c.metrics.efficiency_score.toFixed(2))}
      ${renderMetricCellOld('cost',       '$' + c.metrics.cost_usd.toFixed(4))}
    </div>
  `;
}

function contenderRows(report: ArenaReportView): string {
  return report.contenders.map((contender) => {
    const reviewPaste = contender.review_paste.length > 0
      ? contender.review_paste
      : 'Decision Summary: ' + (contender.hard_gate_pass ? 'Promote contender' : 'Manual review required') + '\nContract Compliance: mandatory_failed=' + contender.mandatory_failed;

    const managerJson = contender.manager_review_json.length > 0
      ? contender.manager_review_json
      : JSON.stringify({
        contender_id: contender.contender_id,
        hard_gate_pass: contender.hard_gate_pass,
        mandatory_failed: contender.mandatory_failed,
        metrics: contender.metrics,
      }, null, 2);

    const hasEval = contender.raw_evaluator_metrics !== null
      && typeof contender.raw_evaluator_metrics === 'object'
      && Object.keys(contender.raw_evaluator_metrics).length > 0;

    const metricsHtml = hasEval
      ? renderEvaluatorMetrics(contender.raw_evaluator_metrics!)
      : renderCanonicalMetrics(contender);

    const gateStyle = contender.hard_gate_pass
      ? 'background:rgba(0,212,170,0.1); color:var(--a-teal); border:1px solid rgba(0,212,170,0.3)'
      : 'background:rgba(255,42,95,0.1); color:var(--a-red); border:1px solid rgba(255,42,95,0.3)';

    return `
      <tr>
        <td>
          <div style="display:grid; gap:0.3rem">
            <span style="font-family:var(--a-mono); font-size:0.8rem">${esc(contender.contender_id)}</span>
            <span style="color:var(--a-dim); font-size:0.75rem">${esc(contender.label)}</span>
            <span style="display:inline-flex; align-items:center; padding:0.2rem 0.5rem; border-radius:4px; font-size:0.68rem; font-weight:700; width:fit-content; font-family:var(--a-mono); ${gateStyle}">${contender.hard_gate_pass ? '✓ PASS' : '✗ FAIL'}</span>
          </div>
        </td>
        <td>
          <div style="font-family:var(--a-mono); font-size:0.78rem">${esc(contender.model)}</div>
          <div style="color:var(--a-dim); font-size:0.72rem">${esc(contender.harness)}</div>
        </td>
        <td>
          <div style="font-family:var(--a-display); font-size:1.2rem; font-weight:800; ${contender.contender_id === report.winner.contender_id ? 'color:var(--a-teal)' : 'color:var(--a-dim)'}">${contender.score.toFixed(1)}</div>
        </td>
        <td style="min-width:240px">${metricsHtml}</td>
        <td style="min-width:220px">
          ${renderReviewPasteInline(reviewPaste)}
          <div style="display:flex; gap:0.35rem; margin-top:0.35rem">
            <button class="arena-copy-btn copy-btn" data-copy="${esc(reviewPaste)}" onclick="navigator.clipboard.writeText(this.getAttribute('data-copy') || ''); this.textContent='Copied';" type="button">Copy Paste</button>
            <button class="arena-copy-btn copy-btn" data-copy="${esc(managerJson)}" onclick="navigator.clipboard.writeText(this.getAttribute('data-copy') || ''); this.textContent='Copied';" type="button">Copy JSON</button>
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

// ─── Review Thread Card ──────────────────────────────────────────────────────

function renderReviewThreadCard(report: ArenaReportView): string {
  if (!Array.isArray(report.review_thread) || report.review_thread.length === 0) {
    return `
      <div class="arena-card">
        <div class="a-label">Decision review thread</div>
        <p style="color:var(--a-dim); font-size:0.82rem; margin-top:0.5rem">No decision paste entries posted yet for this arena.</p>
      </div>
    `;
  }

  const rows = report.review_thread.map((entry) => {
    const isApprove = entry.recommendation === 'APPROVE';
    const badgeStyle = isApprove
      ? 'background:rgba(0,212,170,0.1); color:var(--a-teal); border:1px solid rgba(0,212,170,0.3)'
      : 'background:rgba(255,42,95,0.1); color:var(--a-red); border:1px solid rgba(255,42,95,0.3)';
    const links = entry.links.length > 0
      ? entry.links.map((lnk) => `<a href="${esc(lnk.url)}" target="_blank" rel="noreferrer" class="vs-ev-link">${esc(lnk.label)} ↗</a>`).join(' ')
      : 'none';
    return `
      <tr>
        <td><span style="font-family:var(--a-mono)">${esc(entry.contender_id)}</span></td>
        <td><span style="display:inline-flex; padding:0.2rem 0.55rem; border-radius:4px; font-size:0.65rem; font-weight:700; font-family:var(--a-mono); ${badgeStyle}">${esc(entry.recommendation)}</span></td>
        <td style="font-family:var(--a-mono)">${(entry.confidence * 100).toFixed(1)}%</td>
        <td><div style="display:flex; gap:0.3rem; flex-wrap:wrap">${links}</div></td>
        <td style="font-family:var(--a-mono); font-size:0.75rem; color:var(--a-dim)">${relativeTime(entry.created_at)}</td>
      </tr>
    `;
  }).join('');

  return `
    <div class="arena-card">
      <div class="a-label">Decision review thread</div>
      <p style="color:var(--a-dim); font-size:0.8rem; margin:0.5rem 0 0.75rem">PR/bounty recommendation history with confidence + one-click evidence links.</p>
      <div style="overflow-x:auto">
        <table style="font-size:0.8rem">
          <thead>
            <tr>
              <th>Contender</th>
              <th>Recommendation</th>
              <th>Confidence</th>
              <th>Links</th>
              <th>Posted</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>
  `;
}

// ─── Calibration Card ────────────────────────────────────────────────────────

function renderCalibrationCard(report: ArenaReportView): string {
  const calibration = report.calibration;
  const totals = calibration?.totals;
  if (!totals || totals.samples <= 0) {
    return `
      <div class="arena-card">
        <div class="a-label">Outcome calibration</div>
        <p style="color:var(--a-dim); font-size:0.82rem; margin-top:0.5rem">No outcome feedback recorded yet.</p>
      </div>
    `;
  }

  const reviewerDecisions = totals.reviewer_decisions;
  const topTags = calibration?.reviewer_decision_capture?.decision_taxonomy_tags ?? [];
  const tagLine = topTags.length > 0
    ? topTags.slice(0, 4).map((entry) => esc(entry.tag) + ' (' + entry.count + ')').join(', ')
    : 'none';

  return `
    <div class="arena-card">
      <div class="a-label">Outcome calibration</div>
      <div class="a-diag-grid" style="margin-top:0.75rem; grid-template-columns: repeat(3, minmax(130px, 1fr)); gap:0.4rem">
        ${renderMetricCellOld('samples',        String(totals.samples))}
        ${renderMetricCellOld('override rate',  (totals.override_rate * 100).toFixed(1) + '%')}
        ${renderMetricCellOld('rework rate',    (totals.rework_rate * 100).toFixed(1) + '%')}
        ${renderMetricCellOld('approve decisions', String(reviewerDecisions.approve))}
        ${renderMetricCellOld('request changes',   String(reviewerDecisions.request_changes))}
        ${renderMetricCellOld('reject decisions',  String(reviewerDecisions.reject))}
        ${renderMetricCellOld('avg review min', totals.review_time_avg_minutes.toFixed(1))}
        ${renderMetricCellOld('avg accept min', totals.time_to_accept_avg_minutes.toFixed(1))}
        ${renderMetricCellOld('cost/accepted',  '$' + totals.cost_per_accepted_bounty_usd.toFixed(4))}
      </div>
      <p style="font-family:var(--a-mono); font-size:0.72rem; color:var(--a-dim); margin-top:0.6rem"><strong>Top decision taxonomy tags:</strong> ${tagLine}</p>
    </div>
  `;
}

// ─── ROI Dashboard Card ──────────────────────────────────────────────────────

function renderRoiDashboardCard(report: ArenaReportView): string {
  const roi = report.roi_dashboard;
  if (!roi) {
    return `
      <div class="arena-card">
        <div class="a-label">Arena ROI dashboard</div>
        <p style="color:var(--a-dim); font-size:0.82rem; margin-top:0.5rem">ROI metrics unavailable for this arena payload.</p>
      </div>
    `;
  }

  if (roi.status === 'INSUFFICIENT_SAMPLE' || !roi.metrics) {
    return `
      <div class="arena-card">
        <div class="a-label">Arena ROI dashboard</div>
        <p style="color:var(--a-dim); font-size:0.82rem; margin-top:0.5rem">INSUFFICIENT_SAMPLE — sample_count=${roi.totals.sample_count}, arena_count=${roi.totals.arena_count}.</p>
        <p style="font-family:var(--a-mono); font-size:0.72rem; color:var(--a-dim); margin-top:0.3rem"><strong>Reason codes:</strong> ${esc(roi.reason_codes.join(', ') || 'none')}</p>
      </div>
    `;
  }

  const topReasons = roi.reason_code_drilldown
    .slice(0, 4)
    .map((e) => esc(e.reason_code) + ' (' + e.count + ')')
    .join(', ') || 'none';

  const trend7  = roi.trends.window_7d;
  const trend30 = roi.trends.window_30d;

  return `
    <div class="arena-card">
      <div class="a-label">Arena ROI dashboard</div>
      <p style="color:var(--a-dim); font-size:0.8rem; margin:0.5rem 0 0.75rem">Real persisted outcome metrics for autonomy + throughput quality.</p>
      <div class="a-diag-grid" style="grid-template-columns: repeat(4, minmax(120px, 1fr)); gap:0.35rem; margin-bottom:0.6rem">
        ${renderMetricCellOld('median review min',  roi.metrics.median_review_time_minutes.toFixed(2))}
        ${renderMetricCellOld('first-pass accept',  (roi.metrics.first_pass_accept_rate * 100).toFixed(1) + '%')}
        ${renderMetricCellOld('override rate',      (roi.metrics.override_rate * 100).toFixed(1) + '%')}
        ${renderMetricCellOld('rework rate',        (roi.metrics.rework_rate * 100).toFixed(1) + '%')}
        ${renderMetricCellOld('cost/accepted',      '$' + roi.metrics.cost_per_accepted_bounty_usd.toFixed(4))}
        ${renderMetricCellOld('cycle time min',     roi.metrics.cycle_time_minutes.toFixed(2))}
        ${renderMetricCellOld('winner stability',   (roi.metrics.winner_stability * 100).toFixed(1) + '%')}
        ${renderMetricCellOld('samples',            String(roi.totals.sample_count))}
      </div>
      <div style="display:grid; grid-template-columns:auto 1fr; gap:0.4rem 1rem; font-size:0.8rem; margin-bottom:0.5rem">
        <span style="color:var(--a-dim)">Trend 7d</span><span style="font-family:var(--a-mono)">${esc(trend7.status)} (samples=${trend7.sample_count})</span>
        <span style="color:var(--a-dim)">Trend 30d</span><span style="font-family:var(--a-mono)">${esc(trend30.status)} (samples=${trend30.sample_count})</span>
      </div>
      <p style="font-family:var(--a-mono); font-size:0.72rem; color:var(--a-dim)"><strong>Top reason codes:</strong> ${topReasons}</p>
    </div>
  `;
}

// ─── Autopilot Card ──────────────────────────────────────────────────────────

function renderAutopilotCard(report: ArenaReportView): string {
  const autopilot = report.autopilot;
  if (!autopilot) {
    return `
      <div class="arena-card">
        <div class="a-label">Routing autopilot</div>
        <p style="color:var(--a-dim); font-size:0.82rem; margin-top:0.5rem">Autopilot preview unavailable for this arena payload.</p>
      </div>
    `;
  }

  const isEnabled = autopilot.status === 'auto_route_enabled';
  const violations = autopilot.violations.length > 0 ? autopilot.violations.join(', ') : 'none';
  const statusStyle = isEnabled
    ? 'background:rgba(0,212,170,0.1); color:var(--a-teal); border:1px solid rgba(0,212,170,0.3)'
    : 'background:rgba(255,42,95,0.1); color:var(--a-red); border:1px solid rgba(255,42,95,0.3)';

  return `
    <div class="arena-card ${isEnabled ? 'arena-card-accent-teal' : ''}">
      <div class="a-label">Routing autopilot</div>
      <p style="color:var(--a-dim); font-size:0.8rem; margin:0.5rem 0 0.75rem">Default routing policy preview generated from winner + calibration guardrails.</p>
      <div style="display:flex; align-items:center; gap:0.6rem; margin-bottom:0.75rem; flex-wrap:wrap">
        <span style="display:inline-flex; padding:0.25rem 0.7rem; border-radius:6px; font-size:0.7rem; font-weight:700; font-family:var(--a-display); letter-spacing:0.08em; ${statusStyle}">${esc(autopilot.status)}</span>
        <span style="font-family:var(--a-mono); font-size:0.7rem; color:var(--a-dim)">${esc(autopilot.task_fingerprint ?? 'unknown')}</span>
      </div>
      <div class="a-diag-grid" style="grid-template-columns: repeat(3, minmax(120px, 1fr)); gap:0.35rem; margin-bottom:0.5rem">
        ${renderMetricCellOld('override rate',   (autopilot.metrics.override_rate * 100).toFixed(1) + '%')}
        ${renderMetricCellOld('rework rate',     (autopilot.metrics.rework_rate * 100).toFixed(1) + '%')}
        ${renderMetricCellOld('winner stability', (autopilot.metrics.winner_stability_ratio * 100).toFixed(1) + '%')}
      </div>
      <div style="display:grid; grid-template-columns:auto 1fr; gap:0.4rem 1rem; font-size:0.8rem; margin-bottom:0.4rem">
        <span style="color:var(--a-dim)">Default contender</span><span style="font-family:var(--a-mono)">${esc(autopilot.default_contender_id ?? 'none')}</span>
        <span style="color:var(--a-dim)">Backups</span><span style="font-family:var(--a-mono)">${esc(autopilot.backup_contenders.join(', ') || 'none')}</span>
      </div>
      <p style="font-family:var(--a-mono); font-size:0.72rem; color:var(--a-dim)"><strong>Violations:</strong> ${esc(violations)}</p>
      <p style="font-family:var(--a-mono); font-size:0.72rem; color:var(--a-dim); margin-top:0.3rem"><strong>Reason codes:</strong> ${esc(autopilot.reason_codes.join(', ') || 'none')}</p>
    </div>
  `;
}

// ─── Policy Optimizer Card ───────────────────────────────────────────────────

function renderPolicyOptimizerCard(report: ArenaReportView): string {
  const optimizer = report.policy_optimizer;
  if (!optimizer) {
    return `
      <div class="arena-card">
        <div class="a-label">Routing policy optimizer</div>
        <p style="color:var(--a-dim); font-size:0.82rem; margin-top:0.5rem">No optimizer state available for this arena fingerprint yet.</p>
      </div>
    `;
  }

  const active  = optimizer.current_active_policy;
  const shadow  = optimizer.candidate_shadow_policy;
  const promo   = optimizer.promotion;
  const activeId    = typeof active?.['contender_id']     === 'string' ? active['contender_id']     : 'none';
  const shadowId    = typeof shadow?.['contender_id']     === 'string' ? shadow['contender_id']     : 'none';
  const promoStatus = typeof promo?.['status']            === 'string' ? promo['status'] : (optimizer.promotion_status ?? optimizer.status);
  const promoRc     = Array.isArray(promo?.['reason_codes'])
    ? (promo['reason_codes'] as unknown[]).filter((r): r is string => typeof r === 'string')
    : optimizer.reason_codes;

  return `
    <div class="arena-card">
      <div class="a-label">Routing policy optimizer</div>
      <p style="color:var(--a-dim); font-size:0.8rem; margin:0.5rem 0 0.75rem">Shadow policy computed from real outcomes and promoted only when confidence gates pass.</p>
      <div class="a-diag-grid" style="grid-template-columns: repeat(4, minmax(110px, 1fr)); gap:0.35rem; margin-bottom:0.5rem">
        ${renderMetricCellOld('sample count',   String(optimizer.gates.sample_count))}
        ${renderMetricCellOld('confidence',     (optimizer.gates.confidence_score * 100).toFixed(1) + '%')}
        ${renderMetricCellOld('min samples',    String(optimizer.gates.min_samples))}
        ${renderMetricCellOld('min confidence', (optimizer.gates.min_confidence * 100).toFixed(1) + '%')}
      </div>
      <div style="display:grid; grid-template-columns:auto 1fr; gap:0.4rem 1rem; font-size:0.8rem; margin-bottom:0.4rem">
        <span style="color:var(--a-dim)">Status</span><span style="font-family:var(--a-mono)">${esc(optimizer.status)}</span>
        <span style="color:var(--a-dim)">Promotion status</span><span style="font-family:var(--a-mono)">${esc(promoStatus ?? 'unknown')}</span>
        <span style="color:var(--a-dim)">Active policy contender</span><span style="font-family:var(--a-mono)">${esc(activeId)}</span>
        <span style="color:var(--a-dim)">Shadow policy contender</span><span style="font-family:var(--a-mono)">${esc(shadowId)}</span>
      </div>
      <p style="font-family:var(--a-mono); font-size:0.72rem; color:var(--a-dim)"><strong>Reason codes:</strong> ${esc((promoRc ?? []).join(', ') || 'none')}</p>
    </div>
  `;
}

// ─── Contract Copilot Card ───────────────────────────────────────────────────

function renderContractCopilotCard(report: ArenaReportView): string {
  const copilot = report.contract_copilot;
  if (!copilot) {
    return `
      <div class="arena-card">
        <div class="a-label">Contract Copilot</div>
        <p style="color:var(--a-dim); font-size:0.82rem; margin-top:0.5rem">No copilot suggestions available for this arena payload.</p>
      </div>
    `;
  }

  if (copilot.status === 'empty') {
    return `
      <div class="arena-card">
        <div class="a-label">Contract Copilot</div>
        <p style="color:var(--a-dim); font-size:0.82rem; margin-top:0.5rem">No persisted copilot suggestions for this task fingerprint yet.</p>
      </div>
    `;
  }

  if (copilot.status === 'INSUFFICIENT_SAMPLE') {
    return `
      <div class="arena-card">
        <div class="a-label">Contract Copilot</div>
        <p style="color:var(--a-dim); font-size:0.82rem; margin-top:0.5rem">INSUFFICIENT_SAMPLE — waiting for more real failed outcomes.</p>
      </div>
    `;
  }

  if (copilot.status !== 'available') {
    return `
      <div class="arena-card">
        <div class="a-label">Contract Copilot</div>
        <p style="color:var(--a-dim); font-size:0.82rem; margin-top:0.5rem">Copilot suggestions temporarily unavailable.</p>
      </div>
    `;
  }

  const ranked = [...copilot.global_suggestions, ...copilot.contender_suggestions]
    .sort((a, b) => b.confidence - a.confidence || b.evidence_count - a.evidence_count)
    .slice(0, 5);

  const rows = ranked.map((entry) => {
    const impact = (entry.expected_impact.override_rate_reduction * 100).toFixed(1) + '% / ' + (entry.expected_impact.rework_rate_reduction * 100).toFixed(1) + '%';
    return `
      <tr>
        <td style="font-family:var(--a-mono)">${esc(entry.scope === 'global' ? 'global' : (entry.contender_id ?? 'n/a'))}</td>
        <td style="font-family:var(--a-mono)">${esc(entry.reason_code)}</td>
        <td style="font-family:var(--a-mono)">${(entry.confidence * 100).toFixed(1)}%</td>
        <td style="font-family:var(--a-mono)">${entry.evidence_count} (${entry.source_evidence.length} refs)</td>
        <td style="font-family:var(--a-mono)">${impact}</td>
        <td style="font-size:0.72rem">${esc(entry.before_text)}</td>
        <td style="font-size:0.72rem">${esc(entry.after_text)}</td>
      </tr>
    `;
  }).join('');

  return `
    <div class="arena-card">
      <div class="a-label">Contract Copilot</div>
      <p style="color:var(--a-dim); font-size:0.8rem; margin:0.5rem 0 0.4rem">Rewrite proposals distilled from real override/rework evidence with traceable source rows.</p>
      <p style="font-family:var(--a-mono); font-size:0.72rem; color:var(--a-dim); margin-bottom:0.6rem"><strong>Task fingerprint:</strong> ${esc(copilot.task_fingerprint ?? 'unknown')}</p>
      <div style="overflow-x:auto">
        <table style="font-size:0.78rem">
          <thead>
            <tr>
              <th>Scope</th><th>Reason code</th><th>Confidence</th>
              <th>Evidence</th><th>Expected impact</th><th>Before</th><th>After</th>
            </tr>
          </thead>
          <tbody>${rows || '<tr><td colspan="7" style="color:var(--a-dim)">No copilot suggestions available.</td></tr>'}</tbody>
        </table>
      </div>
    </div>
  `;
}

// ─── Contract Language Optimizer Card ───────────────────────────────────────

function renderContractLanguageOptimizerCard(report: ArenaReportView): string {
  const optimizer = report.contract_language_optimizer;
  if (!optimizer) {
    return `
      <div class="arena-card">
        <div class="a-label">Contract language optimizer</div>
        <p style="color:var(--a-dim); font-size:0.82rem; margin-top:0.5rem">No contract-language optimizer preview available.</p>
      </div>
    `;
  }

  if (optimizer.status === 'empty') {
    return `
      <div class="arena-card">
        <div class="a-label">Contract language optimizer</div>
        <p style="color:var(--a-dim); font-size:0.82rem; margin-top:0.5rem">No failed/overridden outcomes yet for optimizer suggestions.</p>
      </div>
    `;
  }

  if (optimizer.status !== 'available') {
    return `
      <div class="arena-card">
        <div class="a-label">Contract language optimizer</div>
        <p style="color:var(--a-dim); font-size:0.82rem; margin-top:0.5rem">Optimizer suggestions temporarily unavailable.</p>
      </div>
    `;
  }

  const globalRows = optimizer.global_suggestions.slice(0, 4).map((entry) => `
    <tr>
      <td style="font-family:var(--a-mono)">${esc(entry.reason_code)}</td>
      <td style="font-family:var(--a-mono)">${entry.failures}</td>
      <td style="font-family:var(--a-mono)">${(entry.share * 100).toFixed(1)}%</td>
      <td style="font-size:0.72rem">${esc(entry.contract_language_patch)}</td>
    </tr>
  `).join('');

  const contenderRows2 = optimizer.contender_suggestions.slice(0, 6).map((entry) => `
    <tr>
      <td style="font-family:var(--a-mono)">${esc(entry.contender_id ?? 'n/a')}</td>
      <td style="font-family:var(--a-mono)">${esc(entry.reason_code)}</td>
      <td style="font-family:var(--a-mono)">${entry.failures}</td>
      <td style="font-size:0.72rem">${esc(entry.prompt_language_patch)}</td>
    </tr>
  `).join('');

  return `
    <div class="arena-card">
      <div class="a-label">Contract language optimizer</div>
      <p style="color:var(--a-dim); font-size:0.8rem; margin:0.5rem 0 0.4rem">Persisted rewrite suggestions distilled from failed/overridden outcomes.</p>
      <p style="font-family:var(--a-mono); font-size:0.72rem; color:var(--a-dim); margin-bottom:0.5rem"><strong>Task fingerprint:</strong> ${esc(optimizer.task_fingerprint ?? 'unknown')}</p>

      <div class="a-label" style="margin-bottom:0.4rem">Global contract rewrites</div>
      <div style="overflow-x:auto; margin-bottom:0.75rem">
        <table style="font-size:0.78rem">
          <thead><tr><th>Reason code</th><th>Failures</th><th>Share</th><th>Contract patch</th></tr></thead>
          <tbody>${globalRows || '<tr><td colspan="4" style="color:var(--a-dim)">No global suggestions.</td></tr>'}</tbody>
        </table>
      </div>

      <div class="a-label" style="margin-bottom:0.4rem">Contender prompt rewrites</div>
      <div style="overflow-x:auto">
        <table style="font-size:0.78rem">
          <thead><tr><th>Contender</th><th>Reason code</th><th>Failures</th><th>Prompt patch</th></tr></thead>
          <tbody>${contenderRows2 || '<tr><td colspan="4" style="color:var(--a-dim)">No contender-specific suggestions.</td></tr>'}</tbody>
        </table>
      </div>
    </div>
  `;
}

// ─── Outcome Feed Card ───────────────────────────────────────────────────────

function renderOutcomeFeedCard(report: ArenaReportView): string {
  if (!Array.isArray(report.outcomes) || report.outcomes.length === 0) {
    return `
      <div class="arena-card">
        <div class="a-label">Outcome feedback feed</div>
        <p style="color:var(--a-dim); font-size:0.82rem; margin-top:0.5rem">No recorded outcomes for this arena yet.</p>
      </div>
    `;
  }

  const rows = report.outcomes.map((outcome) => {
    const taxonomy = outcome.decision_taxonomy_tags.length > 0
      ? outcome.decision_taxonomy_tags.slice(0, 3).join(', ')
      : 'none';
    const statusColor = outcome.outcome_status === 'ACCEPTED'
      ? 'color:var(--a-teal)'
      : outcome.outcome_status === 'REJECTED' || outcome.outcome_status === 'OVERRIDDEN'
        ? 'color:var(--a-red)'
        : 'color:var(--a-gold)';
    return `
      <tr>
        <td style="font-family:var(--a-mono)">${esc(outcome.contender_id)}</td>
        <td><span style="font-family:var(--a-mono); font-size:0.72rem; font-weight:700; ${statusColor}">${esc(outcome.outcome_status)}</span></td>
        <td style="font-family:var(--a-mono)">${esc(outcome.reviewer_decision)}</td>
        <td style="font-family:var(--a-mono)">${esc(outcome.recommendation)}</td>
        <td style="font-family:var(--a-mono)">${outcome.rework_required ? 'yes' : 'no'}</td>
        <td style="font-family:var(--a-mono)">${esc(outcome.override_reason_code ?? '—')}</td>
        <td style="font-family:var(--a-mono); font-size:0.7rem">${esc(taxonomy)}</td>
        <td style="font-size:0.72rem">${esc(outcome.reviewer_rationale ?? '—')}</td>
        <td style="font-family:var(--a-mono); font-size:0.72rem; color:var(--a-dim)">${relativeTime(outcome.created_at)}</td>
      </tr>
    `;
  }).join('');

  return `
    <div class="arena-card">
      <div class="a-label">Outcome feedback feed</div>
      <div style="overflow-x:auto; margin-top:0.75rem">
        <table style="font-size:0.78rem">
          <thead>
            <tr>
              <th>Contender</th><th>Outcome</th><th>Reviewer decision</th>
              <th>Recommendation</th><th>Rework?</th><th>Override reason</th>
              <th>Decision tags</th><th>Reviewer rationale</th><th>Recorded</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>
  `;
}

// ─── Visual Evidence (old-style layout, updated) ─────────────────────────────

function renderVisualEvidence(report: ArenaReportView, artifactsBaseUrl: string | null): string {
  if (!artifactsBaseUrl || !report.contract?.bounty_id) return '';

  const bountyId = report.contract.bounty_id;
  const steps = ['browse', 'details', 'claim', 'submit'] as const;
  const stepFiles = ['01-browse.png', '02-details.png', '03-claim.png', '04-submit.png'];

  const rows = steps.map((step, idx) => {
    const cols = report.contenders.map((c) => {
      const url = `${artifactsBaseUrl}/arena/${bountyId}/${c.contender_id}/journey/screenshots/${stepFiles[idx]}`;
      return `
        <div style="flex:1; min-width:280px">
          <div style="font-family:var(--a-mono); font-size:0.7rem; color:var(--a-dim); margin-bottom:0.3rem">${esc(c.contender_id)} — ${esc(c.label)}</div>
          <a href="${esc(url)}" target="_blank" rel="noreferrer">
            <img src="${esc(url)}" alt="${esc(step)} screenshot for ${esc(c.contender_id)}"
                 style="width:100%; border-radius:8px; border:1px solid var(--a-border)"
                 loading="lazy" onerror="this.parentElement.innerHTML='<span style=color:var(--a-dim)>Screenshot not available</span>'">
          </a>
        </div>
      `;
    }).join('');
    return `
      <div style="margin-bottom:1.25rem">
        <p style="font-family:var(--a-display); font-size:0.78rem; font-weight:700; color:var(--a-dim); text-transform:capitalize; margin-bottom:0.5rem; letter-spacing:0.08em">${step}</p>
        <div style="display:flex; gap:0.75rem; flex-wrap:wrap">${cols}</div>
      </div>
    `;
  }).join('');

  const timingRows = report.contenders.map((c) => {
    const raw = c.raw_evaluator_metrics;
    const avgMs    = raw && typeof raw.avg_timing_ms        === 'number' ? raw.avg_timing_ms.toFixed(0) + 'ms' : 'N/A';
    const friction = raw && typeof raw.friction_events      === 'number' ? String(raw.friction_events)         : 'N/A';
    const rtErr    = raw && typeof raw.runtime_error_count  === 'number' ? String(raw.runtime_error_count)     : 'N/A';
    const journeyUrl    = `${artifactsBaseUrl}/arena/${bountyId}/${c.contender_id}/journey/journey.json`;
    const lighthouseUrl = `${artifactsBaseUrl}/arena/${bountyId}/${c.contender_id}/lighthouse/lighthouse.summary.json`;
    return `
      <tr>
        <td style="font-family:var(--a-mono)">${esc(c.contender_id)}</td>
        <td>${esc(c.model)}</td>
        <td style="font-family:var(--a-mono)">${avgMs}</td>
        <td>${friction}</td><td>${rtErr}</td>
        <td>
          <a href="${esc(journeyUrl)}" target="_blank" style="font-family:var(--a-mono); font-size:0.72rem; color:var(--a-dim)">journey.json ↗</a>
          &middot;
          <a href="${esc(lighthouseUrl)}" target="_blank" style="font-family:var(--a-mono); font-size:0.72rem; color:var(--a-dim)">lighthouse ↗</a>
        </td>
      </tr>
    `;
  }).join('');

  return `
    <div class="arena-card">
      <div class="a-label">Visual evidence — side-by-side screenshots</div>
      <p style="color:var(--a-dim); font-size:0.75rem; margin:0.5rem 0 0.9rem">Playwright captured each UI flow step. Click to view full size.</p>
      ${rows}
    </div>
    <div class="arena-card">
      <div class="a-label">Journey + Lighthouse data</div>
      <div style="overflow-x:auto; margin-top:0.75rem">
        <table style="font-size:0.8rem">
          <thead><tr><th>Contender</th><th>Model</th><th>Avg Timing</th><th>Friction</th><th>RT Errors</th><th>Raw Data</th></tr></thead>
          <tbody>${timingRows}</tbody>
        </table>
      </div>
    </div>
  `;
}

// ─── pct helper ──────────────────────────────────────────────────────────────

function pct(value: number | null): string {
  if (value === null) return 'n/a';
  return `${(value * 100).toFixed(1)}%`;
}

// ─── Main exported page functions ────────────────────────────────────────────

export function arenaMissionPage(summary: ArenaMissionSummaryView): string {
  const isPass = summary.kpi.gate_status === 'PASS';
  const gateStyle = isPass
    ? 'background:rgba(0,212,170,0.12); color:var(--a-teal); border:1px solid rgba(0,212,170,0.4); font-size:1.1rem; font-weight:800; padding:0.4rem 0.9rem; border-radius:8px; display:inline-block'
    : 'background:rgba(255,42,95,0.12); color:var(--a-red); border:1px solid rgba(255,42,95,0.4); font-size:1.1rem; font-weight:800; padding:0.4rem 0.9rem; border-radius:8px; display:inline-block';

  const subCoverageRate = summary.submissions_window.total > 0
    ? summary.submissions_window.with_submission / summary.submissions_window.total
    : null;

  const gapBountyIds  = summary.backlog.claim_submission_gap_bounty_ids.slice(0, 6);
  const gateReasonCodes = summary.kpi.reason_codes.join(', ') || 'none';

  const meta: PageMeta = {
    title: 'Arena Mission Control',
    description: 'Autonomous Arena mission control dashboard',
    path: '/arena/mission',
  };

  return layout(meta, `
    ${arenaCSS()}
    <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:0.5rem; flex-wrap:wrap; gap:1rem">
      <div>
        <div class="a-title">Arena Mission Control</div>
        <div class="a-subtitle">Operational cockpit for claim → submit throughput, proof quality, and live backlog pressure.</div>
      </div>
      <span style="${gateStyle}; font-family:var(--a-display)">${isPass ? '✓' : '✗'} KPI Gate ${isPass ? 'PASS' : 'FAIL'}</span>
    </div>

    <div class="stats-grid" style="margin-bottom:1.5rem">
      <div class="stat-card">
        <div class="value" style="font-family:var(--a-display); ${isPass ? 'color:var(--a-teal)' : 'color:var(--a-red)'}">${isPass ? 'PASS' : 'FAIL'}</div>
        <div class="label">KPI Gate</div>
      </div>
      <div class="stat-card">
        <div class="value" style="font-family:var(--a-display)">${fmtNum(summary.fleet.online)}</div>
        <div class="label">Fleet Online</div>
      </div>
      <div class="stat-card">
        <div class="value" style="font-family:var(--a-display)">${pct(subCoverageRate)}</div>
        <div class="label">Submission Coverage</div>
      </div>
      <div class="stat-card">
        <div class="value" style="font-family:var(--a-display)">${pct(summary.kpi.proof_valid_rate)}</div>
        <div class="label">Proof Validity</div>
      </div>
    </div>

    <div class="arena-card">
      <div class="a-label">Mission scope + gate rationale</div>
      <div style="display:grid; grid-template-columns:auto 1fr; gap:0.5rem 1.5rem; font-size:0.875rem; margin-top:0.75rem">
        <span style="color:var(--a-dim)">Worker DID</span><span style="font-family:var(--a-mono); word-break:break-all">${esc(summary.worker_did)}</span>
        <span style="color:var(--a-dim)">Window</span><span>${fmtNum(summary.window_hours)}h (since ${relativeTime(summary.window_started_at)})</span>
        <span style="color:var(--a-dim)">Computed</span><span>${relativeTime(summary.computed_at)}</span>
      </div>
      <p style="font-family:var(--a-mono); font-size:0.75rem; color:var(--a-dim); margin-top:0.6rem"><strong>Reason codes:</strong> ${esc(gateReasonCodes)}</p>
    </div>

    <div class="arena-card">
      <div class="a-label">KPI posture</div>
      <div class="a-diag-grid" style="margin-top:0.75rem; grid-template-columns: repeat(4, minmax(130px, 1fr)); gap:0.4rem">
        ${renderMetricCellOld('claim success',      pct(summary.kpi.claim_success_rate))}
        ${renderMetricCellOld('submission success', pct(summary.kpi.submission_success_rate))}
        ${renderMetricCellOld('proof valid rate',   pct(summary.kpi.proof_valid_rate))}
        ${renderMetricCellOld('claim→submit gap',   String(summary.backlog.claim_submission_gap))}
      </div>
      <p style="font-family:var(--a-mono); font-size:0.72rem; color:var(--a-dim); margin-top:0.5rem">Submission coverage is measured from actionable submissions (pending/approved/rejected) over claimed sample.</p>
    </div>

    <div class="arena-card">
      <div class="a-label">Pipeline throughput</div>
      <div class="a-diag-grid" style="margin-top:0.75rem; grid-template-columns: repeat(4, minmax(115px, 1fr)); gap:0.35rem">
        ${renderMetricCellOld('claims total',        String(summary.claims_window.total))}
        ${renderMetricCellOld('claims failed',       String(summary.claims_window.failed))}
        ${renderMetricCellOld('claims skipped',      String(summary.claims_window.skipped))}
        ${renderMetricCellOld('claims processing',   String(summary.claims_window.processing))}
        ${renderMetricCellOld('submissions total',   String(summary.submissions_window.total))}
        ${renderMetricCellOld('with submission',     String(summary.submissions_window.with_submission))}
        ${renderMetricCellOld('without submission',  String(summary.submissions_window.without_submission))}
        ${renderMetricCellOld('proof invalid',       String(summary.submissions_window.proof_invalid))}
        ${renderMetricCellOld('valid pending',       String(summary.submissions_window.pending_review_valid))}
        ${renderMetricCellOld('pending invalid',     String(summary.submissions_window.pending_review_invalid))}
        ${renderMetricCellOld('approved/rejected',   summary.submissions_window.approved + '/' + summary.submissions_window.rejected)}
        ${renderMetricCellOld('accepted backlog',    String(summary.backlog.accepted_without_valid_submission))}
      </div>
    </div>

    <div class="arena-card">
      <div class="a-label">Claim gap queue</div>
      ${gapBountyIds.length === 0
        ? '<p style="color:var(--a-dim); font-size:0.82rem; margin-top:0.5rem">No claim→submission gaps currently tracked in the mission window.</p>'
        : `
          <p style="color:var(--a-dim); font-size:0.8rem; margin:0.5rem 0 0.5rem">Top bounty IDs currently counted in claim→submission gap:</p>
          <ul style="margin-left:1.1rem; display:grid; gap:0.25rem; font-family:var(--a-mono); font-size:0.8rem">
            ${gapBountyIds.map((bountyId) => '<li>' + esc(bountyId) + '</li>').join('')}
          </ul>
        `
      }
    </div>

    <div class="arena-card">
      <div class="a-label">Gate thresholds</div>
      <div style="display:grid; grid-template-columns:auto 1fr; gap:0.5rem 1.5rem; font-size:0.875rem; margin-top:0.75rem">
        <span style="color:var(--a-dim)">Min online workers</span><span>${fmtNum(summary.thresholds.min_online_workers)}</span>
        <span style="color:var(--a-dim)">Min claim success</span><span>${pct(summary.thresholds.min_claim_success_rate)}</span>
        <span style="color:var(--a-dim)">Min submission success</span><span>${pct(summary.thresholds.min_submission_success_rate)}</span>
        <span style="color:var(--a-dim)">Min proof valid</span><span>${pct(summary.thresholds.min_proof_valid_rate)}</span>
        <span style="color:var(--a-dim)">Max claim→submit gap</span><span>${fmtNum(summary.thresholds.max_claim_submission_gap)}</span>
        <span style="color:var(--a-dim)">Max accepted backlog</span><span>${fmtNum(summary.thresholds.max_accepted_backlog)}</span>
      </div>
    </div>
  `);
}

export function arenaComparePage(report: ArenaReportView, artifactsBaseUrl: string | null = null): string {
  const meta: PageMeta = {
    title: `Arena ${report.arena_id}`,
    description: `Bounty Arena comparison for ${report.contract.bounty_id}`,
    path: `/arena/${report.arena_id}`,
  };

  return layout(meta, `
    ${arenaCSS()}

    <!-- page header -->
    <div style="margin-bottom:0.25rem">
      <div class="a-title">Arena Compare: ${esc(report.arena_id)}</div>
      <div class="a-subtitle">Transparent contender comparison across model/harness/tool stack, contract checks, and objective scoring.</div>
    </div>

    <!-- VS Hero Screen -->
    ${vsHeroSection(report)}

    <!-- Live Output Iframe Viewer -->
    ${iframeOutputViewer(report, artifactsBaseUrl)}

    <!-- Screenshot Filmstrip -->
    ${screenshotFilmstrip(report, artifactsBaseUrl)}

    <!-- Score Breakdown Gauges -->
    ${scoreBreakdownSection(report)}

    <!-- Winner Rationale -->
    <div class="arena-card a-section-gap">
      <div class="a-label">Winner rationale + tradeoffs</div>
      <p style="margin:0.75rem 0 0.65rem; font-size:0.9rem">${esc(report.winner.reason)}</p>
      <ul style="margin-left:1.1rem; display:grid; gap:0.3rem; font-size:0.85rem; color:var(--a-dim)">
        ${report.tradeoffs.map((line) => '<li>' + esc(line) + '</li>').join('') || '<li>No tradeoff notes supplied.</li>'}
      </ul>
      <p style="font-family:var(--a-mono); font-size:0.75rem; color:var(--a-dim); margin-top:0.65rem">Reason codes: ${esc(report.reason_codes.join(', ') || 'none')}</p>
    </div>

    <!-- Delegation Insights -->
    ${report.delegation_insights ? `
      <div class="arena-card">
        <div class="a-label">Delegation insights</div>
        <p style="color:var(--a-dim); font-size:0.82rem; margin:0.5rem 0 0.6rem">Route future work using winner hints + observed bottlenecks.</p>
        <div style="display:grid; grid-template-columns:auto 1fr; gap:0.45rem 1.25rem; font-size:0.85rem; margin-bottom:0.6rem">
          <span style="color:var(--a-dim)">Default route</span><span style="font-family:var(--a-mono)">${esc(report.delegation_insights.manager_routing.default_contender_id ?? 'none')}</span>
          <span style="color:var(--a-dim)">Backups</span><span style="font-family:var(--a-mono)">${esc(report.delegation_insights.manager_routing.backup_contenders.join(', ') || 'none')}</span>
        </div>
        <div style="display:grid; gap:0.4rem; font-size:0.83rem">
          <div><strong>Winner hints:</strong> ${esc(report.delegation_insights.winner_hints.join(' | ') || 'none')}</div>
          <div><strong>Bottlenecks:</strong> ${esc(report.delegation_insights.bottlenecks.join(' | ') || 'none')}</div>
          <div><strong>Contract improvements:</strong> ${esc(report.delegation_insights.contract_improvements.join(' | ') || 'none')}</div>
        </div>
      </div>
    ` : ''}

    <!-- Review Thread -->
    ${renderReviewThreadCard(report)}

    <!-- Calibration -->
    ${renderCalibrationCard(report)}

    <!-- ROI Dashboard -->
    ${renderRoiDashboardCard(report)}

    <!-- Autopilot -->
    ${renderAutopilotCard(report)}

    <!-- Policy Optimizer -->
    ${renderPolicyOptimizerCard(report)}

    <!-- Contract Copilot -->
    ${renderContractCopilotCard(report)}

    <!-- Contract Language Optimizer -->
    ${renderContractLanguageOptimizerCard(report)}

    <!-- Outcome Feed -->
    ${renderOutcomeFeedCard(report)}

    <!-- Contract Binding -->
    <div class="arena-card">
      <div class="a-label">Contract binding</div>
      <div style="display:grid; grid-template-columns:auto 1fr; gap:0.5rem 1.5rem; font-size:0.875rem; margin-top:0.75rem">
        <span style="color:var(--a-dim)">Bounty</span><span style="font-family:var(--a-mono)">${esc(report.contract.bounty_id)}</span>
        <span style="color:var(--a-dim)">Contract</span><span style="font-family:var(--a-mono)">${esc(report.contract.contract_id)}</span>
        <span style="color:var(--a-dim)">Contract hash</span><span style="font-family:var(--a-mono); word-break:break-all">${esc(report.contract.contract_hash_b64u)}</span>
        <span style="color:var(--a-dim)">Task fingerprint</span><span style="font-family:var(--a-mono)">${esc(report.contract.task_fingerprint)}</span>
      </div>
    </div>

    <!-- Contenders table (required by tests) -->
    <div class="arena-card" id="proof-card">
      <div class="a-label">Contenders table</div>
      <div style="overflow-x:auto; margin-top:0.75rem">
        <table style="font-size:0.8rem">
          <thead>
            <tr>
              <th>Contender</th>
              <th>Model/Harness</th>
              <th>Score</th>
              <th>Evaluator Metrics</th>
              <th>Review</th>
            </tr>
          </thead>
          <tbody>
            ${contenderRows(report)}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Contract Check Matrix (heatmap) -->
    <div class="arena-card">
      <div class="a-label">Contract check matrix</div>
      <p style="color:var(--a-dim); font-size:0.78rem; margin:0.5rem 0 0.75rem">Hover a cell to see the reason code. Green = PASS with glow. Red = FAIL.</p>
      ${contractCheckMatrix(report)}
    </div>

    <!-- Visual Evidence (screenshots) -->
    ${renderVisualEvidence(report, artifactsBaseUrl)}

    <!-- proof of work note (required "Proof card" text via id above) -->
    <div style="margin-top:1.5rem; font-family:var(--a-mono); font-size:0.65rem; color:var(--a-dim); text-align:center; padding:0.5rem 0; border-top:1px solid var(--a-border)">
      Arena ${esc(report.arena_id)} · Generated ${relativeTime(report.generated_at)} · <a href="#proof-card" style="color:var(--a-dim)">Proof card ↑</a>
    </div>
  `);
}

export function arenaIndexPage(arenas: ArenaIndexItem[]): string {
  const meta: PageMeta = {
    title: 'Arena Index',
    description: 'Bounty Arena comparison history',
    path: '/arena',
  };

  const rows = arenas.length > 0
    ? arenas.map((row) => `
        <tr>
          <td><a href="/arena/${encodeURIComponent(row.arena_id)}" style="font-family:var(--a-mono); color:var(--a-teal)">${esc(row.arena_id)}</a></td>
          <td style="font-family:var(--a-mono)">${esc(row.bounty_id)}</td>
          <td style="font-family:var(--a-mono)">${esc(row.contract_id)}</td>
          <td style="font-family:var(--a-mono)">${esc(row.winner_contender_id)}</td>
          <td><span style="font-family:var(--a-mono); font-size:0.72rem; background:rgba(0,212,170,0.08); border:1px solid rgba(0,212,170,0.25); border-radius:4px; padding:0.15rem 0.45rem; color:var(--a-teal)">${esc(row.reason_code)}</span></td>
          <td style="color:var(--a-dim); font-size:0.82rem">${relativeTime(row.generated_at)}</td>
        </tr>
      `).join('')
    : `
      <tr>
        <td colspan="6">
          <div style="border:1px dashed var(--border); border-radius:8px; padding:1.5rem; background:rgba(255,255,255,0.01); text-align:center">
            <p style="font-family:var(--a-display); font-weight:700">No arena comparisons indexed yet</p>
            <p style="color:var(--a-dim); font-size:0.82rem; margin-top:0.4rem">Run <span style="font-family:var(--a-mono); background:var(--bg-card); padding:0.15rem 0.5rem; border-radius:4px">node scripts/arena/run-bounty-arena.mjs --contract ... --contenders ...</span> and publish arena outputs to activate this feed.</p>
          </div>
        </td>
      </tr>
    `;

  return layout(meta, `
    ${arenaCSS()}

    <div style="display:flex; align-items:flex-end; justify-content:space-between; margin-bottom:1.5rem; flex-wrap:wrap; gap:1rem">
      <div>
        <div class="a-title">Bounty Arena Index</div>
        <div class="a-subtitle" style="margin-bottom:0">Compare contender stacks and copy decision artifacts for human and manager review loops. <a href="/arena/mission" style="color:var(--a-teal)">Open mission control →</a></div>
      </div>
      <span style="font-family:var(--a-mono); font-size:0.72rem; color:var(--a-dim)">${fmtNum(arenas.length)} arenas</span>
    </div>

    <div class="arena-card">
      <div style="overflow-x:auto">
        <table>
          <thead>
            <tr>
              <th>Arena ID</th>
              <th>Bounty</th>
              <th>Contract</th>
              <th>Winner</th>
              <th>Reason Code</th>
              <th>Updated</th>
            </tr>
          </thead>
          <tbody>
            ${rows}
          </tbody>
        </table>
      </div>
    </div>
  `);
}

export function arenaNotFoundPage(arenaId: string): string {
  const meta: PageMeta = {
    title: 'Arena Not Found',
    description: `Arena ${arenaId} was not found.`,
    path: `/arena/${arenaId}`,
  };

  return layout(meta, `
    ${arenaCSS()}
    <div class="arena-card" style="text-align:center; padding:3rem 2rem">
      <div style="font-size:3rem; margin-bottom:1rem; opacity:0.3">⚔</div>
      <div class="a-label" style="justify-content:center; margin-bottom:0.75rem">Arena Not Found</div>
      <p style="font-family:var(--a-mono); margin-bottom:0.5rem; color:var(--a-text)">${esc(arenaId)}</p>
      <p style="color:var(--a-dim); font-size:0.85rem; margin-bottom:1rem">Publish an arena report first, then open this route again.</p>
      <a href="/arena" style="font-family:var(--a-display); font-size:0.78rem; font-weight:700; letter-spacing:0.1em; text-transform:uppercase; color:var(--a-teal); border:1px solid rgba(0,212,170,0.4); border-radius:6px; padding:0.45rem 1rem; text-decoration:none">Open Arena Index →</a>
    </div>
  `);
}

export function sampleArenaMissionSummary(): ArenaMissionSummaryView {
  return {
    schema_version: 'arena_mission_summary.v1',
    computed_at: '2026-02-20T02:18:23.772Z',
    worker_did: 'did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7',
    window_hours: 24,
    window_started_at: '2026-02-19T02:18:23.772Z',
    thresholds: {
      min_online_workers: 3,
      min_claim_success_rate: 0.8,
      min_submission_success_rate: 0.8,
      min_proof_valid_rate: 0.95,
      max_claim_submission_gap: 5,
      max_accepted_backlog: 5,
    },
    fleet: {
      total: 6,
      online: 6,
      offline: 0,
      paused: 0,
    },
    claims_window: {
      processing: 0,
      claimed: 10,
      skipped: 0,
      failed: 0,
      total: 10,
    },
    submissions_window: {
      total: 10,
      with_submission: 10,
      without_submission: 0,
      pending_review_valid: 10,
      pending_review_invalid: 0,
      approved: 0,
      rejected: 0,
      proof_valid: 10,
      proof_invalid: 0,
    },
    backlog: {
      accepted_total: 0,
      accepted_without_valid_submission: 0,
      claim_submission_gap: 0,
      claim_submission_gap_bounty_ids: [],
    },
    kpi: {
      claim_success_rate: 1,
      submission_success_rate: 1,
      proof_valid_rate: 1,
      gate_status: 'PASS',
      reason_codes: ['ARENA_MISSION_KPI_PASS'],
    },
  };
}

export function sampleArenaReport(arenaId: string): ArenaReportView | null {
  if (arenaId !== 'arena_bty_arena_001') return null;

  const contenderChecks = {
    contender_codex_pi: [
      { criterion_id: 'ac_contract_binding', required: true,  status: 'PASS' as const, reason_code: 'CHECK_OK' },
      { criterion_id: 'ac_reason_codes',     required: true,  status: 'PASS' as const, reason_code: 'CHECK_OK' },
      { criterion_id: 'ac_test_coverage',    required: false, status: 'PASS' as const, reason_code: 'CHECK_OK' },
    ],
    contender_claude_codex_cli: [
      { criterion_id: 'ac_contract_binding', required: true,  status: 'PASS' as const, reason_code: 'CHECK_OK' },
      { criterion_id: 'ac_reason_codes',     required: true,  status: 'PASS' as const, reason_code: 'CHECK_OK' },
      { criterion_id: 'ac_test_coverage',    required: false, status: 'FAIL' as const, reason_code: 'ARENA_OPTIONAL_CRITERION_MISS' },
    ],
    contender_gemini_swarm: [
      { criterion_id: 'ac_contract_binding', required: true,  status: 'FAIL' as const, reason_code: 'ARENA_ACCEPTANCE_CRITERION_FAILED' },
      { criterion_id: 'ac_reason_codes',     required: true,  status: 'FAIL' as const, reason_code: 'ARENA_ACCEPTANCE_CRITERION_FAILED' },
      { criterion_id: 'ac_test_coverage',    required: false, status: 'PASS' as const, reason_code: 'CHECK_OK' },
    ],
  };

  return {
    arena_id: 'arena_bty_arena_001',
    generated_at: '2026-02-19T15:10:00.000Z',
    contract: {
      bounty_id: 'bty_arena_001',
      contract_id: 'contract_arena_001',
      contract_hash_b64u: 'RVGH8pYttabUqs0rewkHlUVnxFap8c7lc81vxZi2H7I',
      task_fingerprint: 'typescript:worker:api-hardening',
    },
    objective_profile: {
      name: 'balanced',
      weights: { quality: 0.35, speed: 0.25, cost: 0.2, safety: 0.2 },
      tie_breakers: ['mandatory_passed', 'quality_score', 'risk_score_low', 'cost_low', 'latency_low', 'contender_id'],
    },
    contenders: [
      {
        contender_id: 'contender_codex_pi',
        label: 'Codex + Pi + cloudflare skill',
        model: 'gpt-5.2-codex',
        harness: 'pi',
        tools: ['bash', 'read', 'edit', 'wrangler'],
        skills: ['cloudflare', 'wrangler'],
        plugins: ['did-work'],
        score: 85.5475,
        hard_gate_pass: true,
        mandatory_failed: 0,
        metrics: {
          quality_score: 92,
          risk_score: 26,
          efficiency_score: 81,
          latency_ms: 16000,
          cost_usd: 0.78,
          autonomy_score: 84,
        },
        check_results: contenderChecks.contender_codex_pi,
        score_explain: {
          final_score: 85.5475,
          reason_codes: ['ARENA_SCORE_EVIDENCE_GROUNDED'],
          evidence_links: [
            { label: 'CI',    url: 'https://github.com/clawbureau/clawbureau/actions/runs/22186834424/job/64162890956', source: 'ci' },
            { label: 'Diff',  url: 'https://github.com/clawbureau/clawbureau/pull/366/files',                           source: 'git' },
            { label: 'Trace', url: 'https://github.com/clawbureau/clawbureau/actions/runs/22186834313/job/64162891224', source: 'execution' },
          ],
        },
        review_paste: 'Decision Summary: Promote contender\nContract Compliance: PASS (2 mandatory passed, 0 mandatory failed)\nDelivery/Risk: quality=92.00, risk=26.00, efficiency=81.00, cost=$0.7800, latency=16000ms\nRecommendation: use for high-risk API hardening bounties',
        raw_evaluator_metrics: null,
        manager_review_json: '{\n  "decision": "promote",\n  "confidence": 0.782,\n  "reason_codes": ["ARENA_READY_TO_PROMOTE"]\n}',
      },
      {
        contender_id: 'contender_claude_codex_cli',
        label: 'Claude Opus + Codex CLI blend',
        model: 'claude-opus-4.5',
        harness: 'codex-cli',
        tools: ['bash', 'read', 'edit'],
        skills: ['ai-sdk'],
        plugins: ['did-work'],
        score: 83.0075,
        hard_gate_pass: true,
        mandatory_failed: 0,
        metrics: {
          quality_score: 86,
          risk_score: 38,
          efficiency_score: 90,
          latency_ms: 11200,
          cost_usd: 0.54,
          autonomy_score: 79,
        },
        check_results: contenderChecks.contender_claude_codex_cli,
        score_explain: {
          final_score: 83.0075,
          reason_codes: ['ARENA_SCORE_EVIDENCE_GROUNDED', 'ARENA_OPTIONAL_CHECK_FAILED'],
          evidence_links: [
            { label: 'CI',    url: 'https://github.com/clawbureau/clawbureau/actions/runs/22187189036/job/64164221560', source: 'ci' },
            { label: 'Diff',  url: 'https://github.com/clawbureau/clawbureau/pull/368/files',                           source: 'git' },
            { label: 'Trace', url: 'https://github.com/clawbureau/clawbureau/actions/runs/22187189036/job/64164221560', source: 'execution' },
          ],
        },
        review_paste: 'Decision Summary: Manual review required\nContract Compliance: PASS (2 mandatory passed, 0 mandatory failed)\nDelivery/Risk: quality=86.00, risk=38.00, efficiency=90.00, cost=$0.5400, latency=11200ms\nRecommendation: use for speed-oriented triage work',
        raw_evaluator_metrics: null,
        manager_review_json: '{\n  "decision": "conditional",\n  "confidence": 0.612,\n  "reason_codes": ["ARENA_OPTIONAL_CRITERION_MISS"]\n}',
      },
      {
        contender_id: 'contender_gemini_swarm',
        label: 'Gemini Deep Think + swarm orchestrator',
        model: 'gemini-3.1-pro-preview',
        harness: 'swarm-orchestrator',
        tools: ['bash', 'read', 'edit', 'parallel'],
        skills: ['deep-think-swarm', 'swarm-orchestrator'],
        plugins: ['did-work', 'artifact-tracer'],
        score: 74.655,
        hard_gate_pass: false,
        mandatory_failed: 2,
        metrics: {
          quality_score: 74,
          risk_score: 52,
          efficiency_score: 72,
          latency_ms: 22100,
          cost_usd: 0.31,
          autonomy_score: 69,
        },
        check_results: contenderChecks.contender_gemini_swarm,
        score_explain: {
          final_score: 74.655,
          reason_codes: ['ARENA_SCORE_EVIDENCE_GROUNDED', 'ARENA_EVIDENCE_LINT_FAILED', 'ARENA_MANDATORY_CHECK_FAILED'],
          evidence_links: [
            { label: 'CI',    url: 'https://github.com/clawbureau/clawbureau/actions/runs/22188095506/job/64167593977', source: 'ci' },
            { label: 'Diff',  url: 'https://github.com/clawbureau/clawbureau/pull/370/files',                           source: 'git' },
            { label: 'Trace', url: 'https://github.com/clawbureau/clawbureau/actions/runs/22188095506/job/64167593977', source: 'execution' },
          ],
        },
        review_paste: 'Decision Summary: Reject contender\nContract Compliance: FAIL (0 mandatory passed, 2 mandatory failed)\nDelivery/Risk: quality=74.00, risk=52.00, efficiency=72.00, cost=$0.3100, latency=22100ms\nRecommendation: tighten contract language and rerun',
        raw_evaluator_metrics: null,
        manager_review_json: '{\n  "decision": "reject",\n  "confidence": 0.361,\n  "reason_codes": ["ARENA_MANDATORY_CHECK_FAILED"]\n}',
      },
    ],
    winner: {
      contender_id: 'contender_codex_pi',
      reason: 'Winner contender_codex_pi passed all mandatory checks and achieved top weighted score (85.5475).',
    },
    tradeoffs: [
      'contender_codex_pi wins quality/safety but costs more than contender_claude_codex_cli.',
      'contender_codex_pi trades latency for stronger compliance confidence.',
    ],
    reason_codes: ['ARENA_WINNER_SELECTED', 'ARENA_HARD_GATES_PASSED'],
    delegation_insights: {
      winner_hints: ['use for high-risk API hardening bounties'],
      winner_bottlenecks: ['slower due to larger test matrix'],
      bottlenecks: ['slower due to larger test matrix', 'requires stricter contract language'],
      contract_improvements: ['clarify schema version lock in contract text'],
      next_delegation_hints: [
        'use for high-risk API hardening bounties',
        'pair with low-cost contender for quick reruns',
      ],
      manager_routing: {
        default_contender_id: 'contender_codex_pi',
        backup_contenders: ['contender_claude_codex_cli'],
      },
    },
    review_thread: [
      {
        thread_entry_id: 'art_sample_001',
        contender_id: 'contender_codex_pi',
        recommendation: 'APPROVE',
        confidence: 0.782,
        body_markdown: 'Recommendation: APPROVE',
        links: [
          { label: 'Proof card',       url: '/arena/arena_bty_arena_001#proof-card' },
          { label: 'Arena comparison', url: '/arena/arena_bty_arena_001' },
          { label: 'Review paste',     url: '/arena/arena_bty_arena_001#review-paste-contender_codex_pi' },
          { label: 'Manager review',   url: '/arena/arena_bty_arena_001#manager-review-contender_codex_pi' },
        ],
        source: 'sample',
        created_at: '2026-02-19T15:12:00.000Z',
      },
    ],
    outcomes: [
      {
        outcome_id: 'aot_sample_001',
        contender_id: 'contender_codex_pi',
        outcome_status: 'ACCEPTED',
        review_time_minutes: 18,
        time_to_accept_minutes: 55,
        predicted_confidence: 0.782,
        recommendation: 'APPROVE',
        reviewer_decision: 'approve',
        rework_required: false,
        override_reason_code: null,
        reviewer_rationale: 'All acceptance checks passed with sufficient evidence.',
        decision_taxonomy_tags: ['decision:approve', 'outcome:accepted', 'arena-review'],
        created_at: '2026-02-19T16:00:00.000Z',
      },
    ],
    calibration: {
      totals: {
        samples: 1,
        accepted: 1,
        overridden: 0,
        rework: 0,
        disputed: 0,
        review_time_avg_minutes: 18,
        time_to_accept_avg_minutes: 55,
        cost_per_accepted_bounty_usd: 0.78,
        override_rate: 0,
        rework_rate: 0,
        reviewer_decisions: { approve: 1, request_changes: 0, reject: 0 },
      },
      reviewer_decision_capture: {
        decision_breakdown: [
          { reviewer_decision: 'approve',          count: 1, share: 1 },
          { reviewer_decision: 'request_changes',  count: 0, share: 0 },
          { reviewer_decision: 'reject',           count: 0, share: 0 },
        ],
        decision_taxonomy_tags: [
          { tag: 'decision:approve',  count: 1, share: 1 },
          { tag: 'outcome:accepted',  count: 1, share: 1 },
        ],
      },
    },
    roi_dashboard: {
      status: 'available',
      reason_codes: ['ARENA_ROI_READY'],
      totals: { sample_count: 12, arena_count: 4, available_runs: 4 },
      metrics: {
        median_review_time_minutes: 19.5,
        first_pass_accept_rate: 0.6667,
        override_rate: 0.1667,
        rework_rate: 0.1667,
        cost_per_accepted_bounty_usd: 0.7125,
        cycle_time_minutes: 57,
        winner_stability: 0.75,
      },
      trends: {
        window_7d: {
          status: 'available',
          sample_count: 8,
          reason_codes: [],
          metrics: {
            median_review_time_minutes: 18,
            first_pass_accept_rate: 0.625,
            override_rate: 0.25,
            rework_rate: 0.125,
            cost_per_accepted_bounty_usd: 0.74,
            cycle_time_minutes: 55,
            winner_stability: 0.67,
          },
        },
        window_30d: {
          status: 'available',
          sample_count: 12,
          reason_codes: [],
          metrics: {
            median_review_time_minutes: 19.5,
            first_pass_accept_rate: 0.6667,
            override_rate: 0.1667,
            rework_rate: 0.1667,
            cost_per_accepted_bounty_usd: 0.7125,
            cycle_time_minutes: 57,
            winner_stability: 0.75,
          },
        },
      },
      reason_code_drilldown: [
        { reason_code: 'ARENA_OVERRIDE_SCOPE_MISMATCH', count: 3, share: 0.25 },
        { reason_code: 'ARENA_OVERRIDE_TEST_FAILURE',   count: 2, share: 0.1667 },
      ],
    },
    autopilot: {
      status: 'auto_route_enabled',
      task_fingerprint: 'typescript:worker:api-hardening',
      default_contender_id: 'contender_codex_pi',
      backup_contenders: ['contender_claude_codex_cli'],
      reason_codes: ['ARENA_AUTOPILOT_PREVIEW_ENABLED'],
      violations: [],
      metrics: { override_rate: 0, rework_rate: 0, winner_stability_ratio: 1 },
    },
    contract_copilot: {
      status: 'available',
      task_fingerprint: 'typescript:worker:api-hardening',
      global_suggestions: [
        {
          suggestion_id: 'accs_sample_global_001',
          scope: 'global',
          contender_id: null,
          reason_code: 'ARENA_OVERRIDE_SCOPE_MISMATCH',
          before_text: 'Current contract language under-specifies scope alignment checks for reviewer handoff.',
          after_text: 'Add explicit scope-alignment acceptance criterion with fail-closed escalation and evidence binding.',
          rationale: 'Observed recurrent scope mismatch overrides across multiple arenas.',
          confidence: 0.82,
          evidence_count: 6,
          arena_count: 3,
          outcome_count: 6,
          expected_impact: { override_rate_reduction: 0.34, rework_rate_reduction: 0.21 },
          source_evidence: [
            { arena_id: 'arena_bty_arena_001', outcome_id: 'aot_sample_001', contender_id: 'contender_codex_pi', criterion_id: 'scope_alignment', reason_code: 'ARENA_OVERRIDE_SCOPE_MISMATCH' },
          ],
        },
      ],
      contender_suggestions: [
        {
          suggestion_id: 'accs_sample_contender_001',
          scope: 'contender',
          contender_id: 'contender_claude_codex_cli',
          reason_code: 'ARENA_OVERRIDE_TEST_FAILURE',
          before_text: 'Test completion criteria are too implicit for this contender profile.',
          after_text: 'Require explicit test matrix completion with criterion IDs and CI evidence links.',
          rationale: 'Contender-specific failure pattern shows repeated rework from missing coverage detail.',
          confidence: 0.74,
          evidence_count: 4,
          arena_count: 2,
          outcome_count: 4,
          expected_impact: { override_rate_reduction: 0.26, rework_rate_reduction: 0.29 },
          source_evidence: [
            { arena_id: 'arena_bty_arena_001', outcome_id: 'aot_sample_001', contender_id: 'contender_claude_codex_cli', criterion_id: 'test_coverage', reason_code: 'ARENA_OVERRIDE_TEST_FAILURE' },
          ],
        },
      ],
    },
    contract_language_optimizer: {
      status: 'available',
      task_fingerprint: 'typescript:worker:api-hardening',
      global_suggestions: [
        {
          suggestion_id: 'acls_sample_global_001',
          scope: 'global',
          contender_id: null,
          reason_code: 'ARENA_OVERRIDE_SCOPE_MISMATCH',
          failures: 3,
          overrides: 2,
          share: 0.5,
          priority_score: 3.15,
          contract_rewrite: 'Tighten acceptance criteria and explicit out-of-scope boundaries in the contract.',
          prompt_rewrite: 'Add a scope-check checklist before final answer generation.',
          contract_language_patch: 'Observed 3 failed/overridden outcomes tied to scope mismatch. Add explicit acceptance checklist and out-of-scope boundaries.',
          prompt_language_patch: 'Add a scope-check checklist before final answer generation and fail closed on unmet criteria.',
          sample_notes: ['Winner missed explicit out-of-scope checklist item.'],
          top_tags: ['scope-check', 'acceptance-criteria'],
        },
      ],
      contender_suggestions: [
        {
          suggestion_id: 'acls_sample_contender_001',
          scope: 'contender',
          contender_id: 'contender_codex_pi',
          reason_code: 'ARENA_OVERRIDE_SCOPE_MISMATCH',
          failures: 2,
          overrides: 2,
          share: 1,
          priority_score: 2.1,
          contract_rewrite: 'Tighten acceptance criteria and explicit out-of-scope boundaries in the contract.',
          prompt_rewrite: 'Add a scope-check checklist before final answer generation.',
          contract_language_patch: 'Add contender-specific acceptance checklist for scope-sensitive tasks.',
          prompt_language_patch: 'Require contender to enumerate acceptance criteria and scope exclusions before final output.',
          sample_notes: ['Scope ambiguity caused override for this contender.'],
          top_tags: ['scope-check'],
        },
      ],
    },
  };
}
