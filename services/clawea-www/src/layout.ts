/**
 * Shared HTML layout: shell, nav, footer, breadcrumbs.
 */

import { CSS } from "./styles";
import { metaTags, orgSchema, websiteSchema, breadcrumbSchema, canonical, type PageMeta } from "./seo";

interface LayoutOpts {
  meta: PageMeta;
  body: string;
  breadcrumbs?: { name: string; path: string }[];
  schemas?: string[];
}

export function layout(opts: LayoutOpts): string {
  const { meta, body, breadcrumbs, schemas = [] } = opts;

  const bcHtml = breadcrumbs?.length
    ? `<div class="breadcrumb wrap">${breadcrumbs
        .map((b, i) =>
          i < breadcrumbs.length - 1
            ? `<a href="${b.path}">${b.name}</a><span>/</span>`
            : `<span style="color:var(--text-secondary)">${b.name}</span>`,
        )
        .join("")}</div>`
    : "";

  const bcSchema = breadcrumbs?.length
    ? breadcrumbSchema(breadcrumbs.map((b) => ({ name: b.name, url: canonical(b.path) })))
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  ${metaTags(meta)}
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>&#x1f3e2;</text></svg>">
  <style>${CSS}</style>
  ${orgSchema()}
  ${websiteSchema()}
  ${bcSchema}
  ${schemas.join("\n")}
</head>
<body>
  ${nav()}
  ${bcHtml}
  <main>${body}</main>
  ${footer()}
  ${trackingScript()}
</body>
</html>`;
}

function trackingScript(): string {
  return `<script>
(function(){
  const EVENT_ENDPOINT = "/api/events";
  const STORAGE_KEY = "clawea-attribution-v1";
  const INTENT_PATHS = new Set(["/pricing", "/contact", "/trust", "/secure-workers", "/consulting"]);

  const SAFE_KEYS = [
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "gclid",
    "fbclid",
    "msclkid",
    "referrer_host",
    "landing_path",
    "source",
  ];

  function clip(value, maxLen){
    if (typeof value !== "string") return undefined;
    const v = value.trim();
    if (!v) return undefined;
    return v.slice(0, maxLen);
  }

  function readStored(){
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return {};
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === "object" ? parsed : {};
    } catch {
      return {};
    }
  }

  function writeStored(data){
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
    } catch {
      // ignore storage failures
    }
  }

  function deriveSource(obj){
    if (obj.utm_source) return obj.utm_source;
    if (obj.referrer_host) return "ref:" + obj.referrer_host;
    return "direct";
  }

  function captureAttribution(){
    const current = readStored();
    const next = { ...current };

    const params = new URLSearchParams(window.location.search);

    for (const key of ["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "gclid", "fbclid", "msclkid"]) {
      const v = clip(params.get(key), 160);
      if (v) next[key] = v;
    }

    if (!next.landing_path) {
      next.landing_path = clip(window.location.pathname, 200) || "/";
    }

    if (!next.referrer_host && document.referrer) {
      try {
        const host = new URL(document.referrer).hostname.toLowerCase();
        if (host && host !== window.location.hostname.toLowerCase()) {
          next.referrer_host = clip(host, 120);
        }
      } catch {
        // ignore invalid referrer
      }
    }

    next.source = deriveSource(next);
    writeStored(next);
    return next;
  }

  function currentAttribution(){
    const stored = readStored();
    const out = {};
    for (const key of SAFE_KEYS) {
      const v = clip(stored[key], 160);
      if (v) out[key] = v;
    }
    if (!out.source) out.source = deriveSource(out);
    return out;
  }

  function appendAttributionToHref(href){
    try {
      const base = new URL(href, window.location.origin);
      if (base.origin !== window.location.origin) return href;

      const attrs = currentAttribution();
      for (const key of ["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content"]) {
        if (attrs[key] && !base.searchParams.has(key)) {
          base.searchParams.set(key, attrs[key]);
        }
      }
      if (attrs.source && !base.searchParams.has("src")) {
        base.searchParams.set("src", attrs.source);
      }
      return base.pathname + base.search + base.hash;
    } catch {
      return href;
    }
  }

  function sendEvent(payload){
    const body = JSON.stringify(payload);
    if (navigator.sendBeacon) {
      const blob = new Blob([body], { type: "application/json" });
      navigator.sendBeacon(EVENT_ENDPOINT, blob);
      return;
    }

    fetch(EVENT_ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
      keepalive: true,
    }).catch(() => {});
  }

  function track(eventType, extra){
    sendEvent({
      eventType,
      ts: new Date().toISOString(),
      page: window.location.pathname,
      attribution: currentAttribution(),
      ...(extra || {}),
    });
  }

  captureAttribution();

  document.querySelectorAll("a[href]").forEach((el) => {
    const hrefAttr = clip(el.getAttribute("href"), 600);
    if (!hrefAttr) return;

    const isMailto = hrefAttr.toLowerCase().startsWith("mailto:");
    const isCta = Boolean(el.classList.contains("cta-btn") || el.getAttribute("data-cta"));

    if (isCta && hrefAttr.startsWith("/")) {
      el.setAttribute("href", appendAttributionToHref(hrefAttr));
    }

    if (!isCta && !isMailto) return;

    el.addEventListener("click", () => {
      const href = clip(el.getAttribute("href"), 600);
      const ctaId = clip(el.getAttribute("data-cta") || el.textContent || "cta", 120);

      if (href && href.toLowerCase().startsWith("mailto:")) {
        track("contact_email_click", { href, ctaId });
      } else {
        track("cta_click", { href, ctaId });
      }
    }, { passive: true });
  });

  if (INTENT_PATHS.has(window.location.pathname)) {
    track("contact_intent_view", { ctaId: window.location.pathname });
  }
})();
</script>`;
}

function nav(): string {
  return `
  <nav>
    <div class="wrap">
      <a href="/" class="logo">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
        </svg>
        claw<span>ea</span>
      </a>
      <div class="links">
        <a href="/controls">Controls</a>
        <a href="/workflows">Workflows</a>
        <a href="/tools">Tools</a>
        <a href="/channels">Channels</a>
        <a href="/trust">Trust</a>
        <a href="/pricing">Pricing</a>
        <a href="/contact" class="cta-btn">Talk to Sales</a>
      </div>
    </div>
  </nav>`;
}

function footer(): string {
  return `
  <footer>
    <div class="wrap">
      <div>
        <h4>Claw Enterprise Agents</h4>
        <p style="color:var(--text-muted);font-size:.85rem;max-width:280px;line-height:1.6">
          Deploy permissioned AI agents for enterprise teams.
          Policy-as-code controls, approvals, and proof bundles,
          so you can ship automation without losing auditability.
        </p>
      </div>
      <div>
        <h4>Platform</h4>
        <ul>
          <li><a href="/controls">Controls</a></li>
          <li><a href="/workflows">Workflows</a></li>
          <li><a href="/tools">Tools</a></li>
          <li><a href="/channels">Channels</a></li>
          <li><a href="/mcp">MCP</a></li>
          <li><a href="/compliance">Compliance</a></li>
          <li><a href="/trust">Trust</a></li>
          <li><a href="/secure-workers">Secure Workers</a></li>
        </ul>
      </div>
      <div>
        <h4>Microsoft</h4>
        <ul>
          <li><a href="/tools/entra-id">Entra ID</a></li>
          <li><a href="/tools/sharepoint">SharePoint</a></li>
          <li><a href="/tools/outlook-exchange">Outlook / Exchange</a></li>
          <li><a href="/tools/azure-devops">Azure DevOps</a></li>
          <li><a href="/tools/microsoft-purview">Purview</a></li>
        </ul>
      </div>
      <div>
        <h4>Resources</h4>
        <ul>
          <li><a href="/guides">Guides</a></li>
          <li><a href="/glossary">Glossary</a></li>
          <li><a href="/mcp-security">MCP Security</a></li>
          <li><a href="/about">About</a></li>
          <li><a href="/contact">Contact</a></li>
        </ul>
      </div>
      <div class="copyright">
        &copy; ${new Date().getFullYear()} Claw Bureau. All rights reserved.
        <span style="margin:0 .5rem">|</span>
        <a href="https://clawbureau.com">clawbureau.com</a>
        <span style="margin:0 .5rem">|</span>
        <a href="https://clawverify.com">clawverify.com</a>
        <span style="margin:0 .5rem">|</span>
        <a href="https://clawbounties.com">clawbounties.com</a>
      </div>
    </div>
  </footer>`;
}
