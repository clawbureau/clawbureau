/**
 * Agent Profile Page: GET /agent/:did
 *
 * Displays:
 * - Agent DID (truncated with copy)
 * - Reputation metrics: total runs, gateway tier %, violation count
 * - Run history table (paginated)
 * - Verification streak
 * - Embed snippet (JSON-LD for EIP-8004)
 */

import {
  layout, esc, didDisplay, statusBadge, tierBadge,
  relativeTime, fmtNum, type PageMeta,
} from "../layout.js";

export interface AgentPassport {
  did: string;
  first_seen_at: string;
  verified_runs: number;
  gateway_tier_runs: number;
  policy_violations: number;
}

export interface AgentRun {
  run_id: string;
  proof_tier: string;
  status: string;
  created_at: string;
  models: Array<{ provider: string; model: string }>;
}

export interface AgentPageData {
  passport: AgentPassport;
  runs: AgentRun[];
  page: number;
  total_runs: number;
  has_next: boolean;
}

export function agentProfilePage(data: AgentPageData): string {
  const { passport, runs } = data;
  const shortDid = passport.did.length > 32
    ? passport.did.slice(0, 20) + "..." + passport.did.slice(-8)
    : passport.did;

  const meta: PageMeta = {
    title: `Agent ${shortDid}`,
    description: `Agent ${shortDid} -- ${passport.verified_runs} verified runs, ${passport.gateway_tier_runs} gateway tier, ${passport.policy_violations} violations.`,
    path: `/agent/${encodeURIComponent(passport.did)}`,
    ogType: "profile",
  };

  const gatewayPct = passport.verified_runs > 0
    ? Math.round((passport.gateway_tier_runs / passport.verified_runs) * 100)
    : 0;

  // Compute verification streak (consecutive PASS runs from most recent)
  let streak = 0;
  for (const run of runs) {
    if (run.status === "PASS") streak++;
    else break;
  }

  const runsTableHtml = runs.length > 0
    ? `
      <table>
        <thead>
          <tr>
            <th>Run ID</th>
            <th>Tier</th>
            <th>Status</th>
            <th>Models</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          ${runs.map(r => `
            <tr>
              <td><a href="/run/${esc(r.run_id)}" class="mono" style="font-size: 0.8125rem">${esc(r.run_id.slice(0, 16))}...</a></td>
              <td>${tierBadge(r.proof_tier)}</td>
              <td>${statusBadge(r.status)}</td>
              <td class="dim" style="font-size: 0.8125rem">${r.models.map(m => esc(m.model)).join(", ") || "\u2014"}</td>
              <td class="dim" style="font-size: 0.8125rem">${relativeTime(r.created_at)}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
      ${paginationHtml(data)}
    `
    : `<p class="dim">No runs recorded yet.</p>`;

  const embedSnippet = jsonLdSnippet(passport);

  const body = `
    <div style="margin-bottom: 1.5rem">
      <a href="/" class="dim" style="font-size: 0.8125rem">&larr; Explorer</a>
    </div>

    <h1 class="page-title">Agent Profile</h1>
    <div style="margin-bottom: 2rem">
      ${didDisplay(passport.did)}
      <span class="dim" style="font-size: 0.8125rem; margin-left: 0.75rem">
        since ${esc(passport.first_seen_at.slice(0, 10))}
      </span>
    </div>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="value">${fmtNum(passport.verified_runs)}</div>
        <div class="label">Verified Runs</div>
      </div>
      <div class="stat-card">
        <div class="value">${gatewayPct}%</div>
        <div class="label">Gateway Tier</div>
      </div>
      <div class="stat-card">
        <div class="value" style="color: ${passport.policy_violations > 0 ? "var(--fail)" : "var(--pass)"}">${fmtNum(passport.policy_violations)}</div>
        <div class="label">Violations</div>
      </div>
      <div class="stat-card">
        <div class="value">${fmtNum(streak)}</div>
        <div class="label">Current Streak</div>
      </div>
    </div>

    <div class="card">
      <p class="section-title">Run History</p>
      ${runsTableHtml}
    </div>

    <div class="card">
      <p class="section-title">Embed This Passport (JSON-LD / EIP-8004)</p>
      <pre class="mono" style="background: var(--bg); padding: 1rem; border-radius: 4px; overflow-x: auto; font-size: 0.75rem; border: 1px solid var(--border)">${esc(embedSnippet)}</pre>
      <button class="copy-btn" style="margin-top: 0.75rem" onclick="navigator.clipboard.writeText(document.querySelector('pre').textContent)">Copy snippet</button>
    </div>
  `;

  return layout(meta, body);
}

function paginationHtml(data: AgentPageData): string {
  if (data.total_runs <= 20) return "";

  const prevPage = data.page > 1 ? data.page - 1 : null;
  const nextPage = data.has_next ? data.page + 1 : null;
  const base = `/agent/${encodeURIComponent(data.passport.did)}`;

  return `
    <div style="display: flex; justify-content: space-between; margin-top: 1rem; font-size: 0.875rem">
      ${prevPage ? `<a href="${base}?page=${prevPage}">&larr; Previous</a>` : `<span></span>`}
      <span class="dim">Page ${data.page}</span>
      ${nextPage ? `<a href="${base}?page=${nextPage}">Next &rarr;</a>` : `<span></span>`}
    </div>
  `;
}

function jsonLdSnippet(passport: AgentPassport): string {
  const ld = {
    "@context": "https://schema.org",
    "@type": "SoftwareAgent",
    "identifier": passport.did,
    "url": `https://explorer.clawsig.com/agent/${encodeURIComponent(passport.did)}`,
    "additionalProperty": [
      {
        "@type": "PropertyValue",
        "propertyID": "clawsig:verified_runs",
        "value": passport.verified_runs,
      },
      {
        "@type": "PropertyValue",
        "propertyID": "clawsig:gateway_tier_runs",
        "value": passport.gateway_tier_runs,
      },
      {
        "@type": "PropertyValue",
        "propertyID": "clawsig:policy_violations",
        "value": passport.policy_violations,
      },
    ],
  };
  return JSON.stringify(ld, null, 2);
}

export function agentNotFoundPage(did: string): string {
  const meta: PageMeta = {
    title: "Agent Not Found",
    description: `Agent ${did} was not found in the public ledger.`,
    path: `/agent/${encodeURIComponent(did)}`,
  };

  const body = `
    <div style="text-align: center; padding: 4rem 0">
      <h1 class="page-title">Agent Not Found</h1>
      <p class="dim" style="margin-bottom: 2rem">
        Agent <span class="mono">${esc(did.slice(0, 40))}${did.length > 40 ? "..." : ""}</span> was not found in the public ledger.
      </p>
      <p>
        <a href="/">Back to Explorer &rarr;</a>
      </p>
    </div>
  `;

  return layout(meta, body);
}
