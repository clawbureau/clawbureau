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
  <a href="#main-content" class="skip-link">Skip to content</a>
  <div class="progress-bar" role="progressbar" aria-hidden="true"></div>
  ${nav(meta.path)}
  ${bcHtml}
  <main id="main-content">${body}</main>
  ${footer()}
  <a href="#" class="back-to-top" aria-label="Back to top">&uarr;</a>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  ${interactiveScript()}
  ${trackingScript()}
</body>
</html>`;
}

function interactiveScript(): string {
  return `<script>
(function(){
  /* Mobile nav toggle */
  var toggle=document.querySelector('.nav-toggle');
  var menu=document.getElementById('nav-menu');
  if(toggle&&menu){
    toggle.addEventListener('click',function(){
      var expanded=toggle.getAttribute('aria-expanded')==='true';
      toggle.setAttribute('aria-expanded',String(!expanded));
      menu.classList.toggle('open');
      if(!expanded){document.body.style.overflow='hidden';}
      else{document.body.style.overflow='';}
    });
    menu.querySelectorAll('a').forEach(function(a){
      a.addEventListener('click',function(){
        toggle.setAttribute('aria-expanded','false');
        menu.classList.remove('open');
        document.body.style.overflow='';
      });
    });
    document.addEventListener('keydown',function(e){
      if(e.key==='Escape'&&menu.classList.contains('open')){
        toggle.setAttribute('aria-expanded','false');
        menu.classList.remove('open');
        document.body.style.overflow='';
      }
    });
  }

  /* Global search shortcut (/) + live search */
  var searchForms=document.querySelectorAll('.nav-search');
  var searchInputs=document.querySelectorAll('[data-global-search]');

  function isEditable(el){
    if(!el||!(el instanceof HTMLElement))return false;
    var tag=(el.tagName||'').toLowerCase();
    return tag==='input'||tag==='textarea'||tag==='select'||el.isContentEditable;
  }

  function trackSearch(eventType,payload){
    if(window.__claweaTrack){
      window.__claweaTrack(eventType,payload||{});
      return;
    }
    try {
      var body=JSON.stringify({
        eventType:eventType,
        ts:new Date().toISOString(),
        page:window.location.pathname,
        pageFamily:'search',
        ...(payload||{})
      });
      if(navigator.sendBeacon){
        navigator.sendBeacon('/api/events',new Blob([body],{type:'application/json'}));
      } else {
        fetch('/api/events',{method:'POST',headers:{'content-type':'application/json'},body:body,keepalive:true}).catch(function(){});
      }
    } catch {}
  }

  document.addEventListener('keydown',function(e){
    if(e.defaultPrevented||e.key!=='/'||e.metaKey||e.ctrlKey||e.altKey)return;
    if(isEditable(document.activeElement))return;

    var target=null;
    for(var i=0;i<searchInputs.length;i++){
      var candidate=searchInputs[i];
      if(candidate&&candidate.offsetParent!==null){target=candidate;break;}
    }
    if(!target&&searchInputs.length>0)target=searchInputs[0];
    if(!target)return;

    e.preventDefault();
    target.focus();
    if(typeof target.select==='function')target.select();
  });

  searchForms.forEach(function(form){
    var input=form.querySelector('[data-global-search]');
    var clearBtn=form.querySelector('[data-search-clear]');
    var resultsEl=form.querySelector('[data-search-results]');
    if(!input||!resultsEl)return;

    var controller=null;
    var debounceTimer=null;
    var activeIndex=-1;
    var currentQuery='';
    var currentResults=[];

    function setClearVisible(visible){
      if(!clearBtn)return;
      if(visible){clearBtn.removeAttribute('hidden');}
      else{clearBtn.setAttribute('hidden','');}
    }

    function closeResults(){
      resultsEl.setAttribute('hidden','');
      resultsEl.innerHTML='';
      resultsEl.removeAttribute('aria-activedescendant');
      activeIndex=-1;
      currentResults=[];
    }

    function renderResults(query,items){
      currentQuery=query;
      currentResults=items||[];
      activeIndex=-1;

      if(!items||items.length===0){
        resultsEl.innerHTML='<div class="nav-search-empty">No matching pages</div>';
        resultsEl.removeAttribute('hidden');
        return;
      }

      resultsEl.innerHTML=items.map(function(item,idx){
        return '<a class="nav-search-result" role="option" id="nav-search-opt-'+idx+'" href="'+item.path+'" data-search-target="'+item.path+'">'
          +'<span class="nav-search-result-title">'+item.title.replace(/</g,'&lt;').replace(/>/g,'&gt;')+'</span>'
          +'<span class="nav-search-result-meta">'+item.path+' · '+item.category+'</span>'
          +'</a>';
      }).join('');
      resultsEl.removeAttribute('hidden');

      resultsEl.querySelectorAll('a[data-search-target]').forEach(function(link){
        link.addEventListener('click',function(){
          var targetPath=link.getAttribute('data-search-target')||undefined;
          trackSearch('search_result_click',{
            query: currentQuery,
            resultCount: currentResults.length,
            targetPath: targetPath,
            actionOutcome: 'clicked'
          });
        },{passive:true});
      });
    }

    function updateActiveResult(next){
      var options=resultsEl.querySelectorAll('.nav-search-result');
      if(options.length===0)return;
      activeIndex=(next+options.length)%options.length;
      options.forEach(function(opt){opt.classList.remove('active');});
      var active=options[activeIndex];
      if(active){
        active.classList.add('active');
        resultsEl.setAttribute('aria-activedescendant',active.id||'');
        active.scrollIntoView({block:'nearest'});
      }
    }

    async function fetchResults(query){
      if(controller){controller.abort();}
      controller=new AbortController();

      try {
        var res=await fetch('/api/search?q='+encodeURIComponent(query)+'&limit=8',{signal:controller.signal});
        if(!res.ok){closeResults();return;}
        var payload=await res.json();
        var items=Array.isArray(payload&&payload.results)?payload.results:[];
        renderResults(query,items);
        trackSearch('search_query',{
          query: query,
          resultCount: items.length,
          actionOutcome: items.length>0?'results':'empty'
        });
      } catch(err){
        if(err&&err.name==='AbortError')return;
        closeResults();
      }
    }

    input.addEventListener('input',function(){
      var q=(input.value||'').trim();
      setClearVisible(Boolean(q));

      if(debounceTimer)clearTimeout(debounceTimer);

      if(q.length<2){
        closeResults();
        return;
      }

      debounceTimer=setTimeout(function(){fetchResults(q);},180);
    });

    input.addEventListener('keydown',function(e){
      if(e.key==='ArrowDown'){
        e.preventDefault();
        updateActiveResult(activeIndex+1);
      } else if(e.key==='ArrowUp'){
        e.preventDefault();
        updateActiveResult(activeIndex-1);
      } else if(e.key==='Escape'){
        closeResults();
      } else if(e.key==='Enter'){
        if(activeIndex>=0&&currentResults[activeIndex]){
          e.preventDefault();
          window.location.href=currentResults[activeIndex].path;
        }
      }
    });

    if(clearBtn){
      clearBtn.addEventListener('click',function(){
        input.value='';
        input.focus();
        closeResults();
        setClearVisible(false);
        trackSearch('search_clear',{actionOutcome:'cleared'});
      });
    }

    form.addEventListener('submit',function(e){
      var q=(input.value||'').trim();
      if(!q){
        e.preventDefault();
        window.location.href='/glossary';
      }
    });

    document.addEventListener('click',function(e){
      if(form.contains(e.target))return;
      closeResults();
    });
  });

  /* Reading progress bar */
  var bar=document.querySelector('.progress-bar');
  if(bar){
    var ticking=false;
    window.addEventListener('scroll',function(){
      if(!ticking){requestAnimationFrame(function(){
        var h=document.documentElement.scrollHeight-window.innerHeight;
        bar.style.width=h>0?((window.scrollY/h)*100)+'%':'0%';
        ticking=false;
      });ticking=true;}
    },{passive:true});
  }

  /* Back to top */
  var btt=document.querySelector('.back-to-top');
  if(btt){
    window.addEventListener('scroll',function(){
      btt.classList.toggle('visible',window.scrollY>600);
    },{passive:true});
    btt.addEventListener('click',function(e){
      e.preventDefault();
      window.scrollTo({top:0,behavior:'smooth'});
    });
  }

  /* FAQ accordion semantics + keyboard nav */
  var accordions=document.querySelectorAll('[data-accordion]');
  accordions.forEach(function(acc){
    var triggers=Array.prototype.slice.call(acc.querySelectorAll('[data-accordion-trigger]'));
    if(triggers.length===0)return;

    function setExpanded(trigger,expanded){
      trigger.setAttribute('aria-expanded',String(expanded));
      var panelId=trigger.getAttribute('aria-controls');
      if(!panelId)return;
      var panel=document.getElementById(panelId);
      if(!panel)return;
      if(expanded)panel.removeAttribute('hidden');
      else panel.setAttribute('hidden','');
    }

    function openOnly(target){
      triggers.forEach(function(trigger){
        setExpanded(trigger,trigger===target);
      });
    }

    triggers.forEach(function(trigger,index){
      trigger.addEventListener('click',function(){
        var isOpen=trigger.getAttribute('aria-expanded')==='true';
        if(isOpen){setExpanded(trigger,false);return;}
        openOnly(trigger);
      });

      trigger.addEventListener('keydown',function(e){
        var next=index;
        if(e.key==='ArrowDown')next=(index+1)%triggers.length;
        else if(e.key==='ArrowUp')next=(index-1+triggers.length)%triggers.length;
        else if(e.key==='Home')next=0;
        else if(e.key==='End')next=triggers.length-1;
        else return;

        e.preventDefault();
        triggers[next].focus();
      });
    });
  });

  /* TOC active heading tracking */
  var tocLinks=document.querySelectorAll('.toc a');
  if(tocLinks.length>0){
    var headings=[];
    tocLinks.forEach(function(a){
      var id=(a.getAttribute('href')||'').slice(1);
      var el=id&&document.getElementById(id);
      if(el)headings.push({el:el,link:a});
    });
    var tocTicking=false;
    window.addEventListener('scroll',function(){
      if(!tocTicking){requestAnimationFrame(function(){
        var current=null;
        for(var i=0;i<headings.length;i++){
          if(headings[i].el.getBoundingClientRect().top<=120)current=headings[i];
        }
        tocLinks.forEach(function(a){a.classList.remove('active');});
        if(current)current.link.classList.add('active');
        tocTicking=false;
      });tocTicking=true;}
    },{passive:true});
  }
})();
</script>`;
}

function trackingScript(): string {
  return `<script>
(function(){
  const EVENT_ENDPOINT = "/api/events";
  const LEAD_ENDPOINT = "/api/leads/submit";
  const STORAGE_KEY = "clawea-attribution-v2";
  const INTENT_PATHS = new Set(["/pricing", "/contact", "/assessment", "/assessment/result", "/trust", "/secure-workers", "/consulting"]);

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
    "first_touch_ts",
    "first_touch_path",
    "first_touch_page_family"
  ];

  function clip(value, maxLen){
    if (typeof value !== "string") return undefined;
    const v = value.trim();
    if (!v) return undefined;
    return v.slice(0, maxLen);
  }

  function derivePageFamily(pathname){
    const path = (pathname || '/').replace(/^\/+|\/+$/g, '');
    if (!path) return 'home';
    const first = path.split('/')[0];
    const known = new Set([
      'controls','workflows','tools','channels','policy','proof','verify','audit',
      'mcp','supply-chain','events','compliance','guides','glossary','sources',
      'trust','secure-workers','consulting','pricing','contact','about','assessment'
    ]);
    return known.has(first) ? first : 'root';
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
    } catch {}
  }

  function deriveSource(obj){
    if (obj.utm_source) return obj.utm_source;
    if (obj.referrer_host) return "ref:" + obj.referrer_host;
    return "direct";
  }

  function parseCookieMap(){
    const out = {};
    const raw = document.cookie || "";
    raw.split(';').forEach(function(entry){
      const e = entry.trim();
      if(!e) return;
      const idx = e.indexOf('=');
      if(idx <= 0) return;
      const k = e.slice(0, idx);
      const v = e.slice(idx + 1);
      out[k] = decodeURIComponent(v || '');
    });
    return out;
  }

  function currentVisitorId(){
    const cookies = parseCookieMap();
    const vid = clip(cookies.clawea_vid, 140);
    return vid || undefined;
  }

  function experimentFromCookie(){
    const cookies = parseCookieMap();
    const raw = clip(cookies.clawea_exp, 240);
    if (!raw) {
      return {
        variantId: derivePageFamily(window.location.pathname) + ":proof:sales",
        heroVariant: "proof",
        ctaVariant: "sales",
      };
    }

    const parts = raw.split(':');
    if (parts.length < 3) {
      return {
        variantId: derivePageFamily(window.location.pathname) + ":proof:sales",
        heroVariant: "proof",
        ctaVariant: "sales",
      };
    }

    return {
      variantId: parts[0] + ':' + parts[1] + ':' + parts[2],
      heroVariant: parts[1],
      ctaVariant: parts[2],
    };
  }

  function captureAttribution(){
    const current = readStored();
    const next = { ...current };

    const params = new URLSearchParams(window.location.search);
    ["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "gclid", "fbclid", "msclkid"].forEach(function(key){
      const v = clip(params.get(key), 160);
      if (v) next[key] = v;
    });

    if (!next.landing_path) {
      next.landing_path = clip(window.location.pathname, 200) || "/";
    }

    if (!next.first_touch_ts) {
      next.first_touch_ts = new Date().toISOString();
    }
    if (!next.first_touch_path) {
      next.first_touch_path = clip(window.location.pathname, 200) || "/";
    }
    if (!next.first_touch_page_family) {
      next.first_touch_page_family = derivePageFamily(window.location.pathname);
    }

    if (!next.referrer_host && document.referrer) {
      try {
        const host = new URL(document.referrer).hostname.toLowerCase();
        if (host && host !== window.location.hostname.toLowerCase()) {
          next.referrer_host = clip(host, 120);
        }
      } catch {}
    }

    next.source = deriveSource(next);
    writeStored(next);
    return next;
  }

  function currentAttribution(){
    const stored = readStored();
    const out = {};
    SAFE_KEYS.forEach(function(key){
      const v = clip(stored[key], 160);
      if (v) out[key] = v;
    });
    if (!out.source) out.source = deriveSource(out);
    return out;
  }

  function appendAttributionToHref(href){
    try {
      const base = new URL(href, window.location.origin);
      if (base.origin !== window.location.origin) return href;

      const attrs = currentAttribution();
      ["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content"].forEach(function(key){
        if (attrs[key] && !base.searchParams.has(key)) {
          base.searchParams.set(key, attrs[key]);
        }
      });
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
    }).catch(function(){});
  }

  function track(eventType, extra){
    const exp = experimentFromCookie();
    sendEvent({
      eventType,
      ts: new Date().toISOString(),
      page: window.location.pathname,
      pageFamily: derivePageFamily(window.location.pathname),
      attribution: currentAttribution(),
      variantId: exp.variantId,
      heroVariant: exp.heroVariant,
      ctaVariant: exp.ctaVariant,
      visitorId: currentVisitorId(),
      ...(extra || {}),
    });
  }

  window.__claweaTrack = track;

  function applyVariantCopy(){
    const exp = experimentFromCookie();

    document.querySelectorAll('[data-hero-copy]').forEach(function(el){
      var attr = 'data-hero-' + exp.heroVariant;
      var next = clip(el.getAttribute(attr), 220);
      if (next) el.textContent = next;
    });

    document.querySelectorAll('[data-cta-copy]').forEach(function(el){
      var attr = 'data-cta-' + exp.ctaVariant;
      var next = clip(el.getAttribute(attr), 200);
      if (next) el.textContent = next;
      el.setAttribute('data-cta-variant', exp.ctaVariant);
    });
  }

  function markVariantImpression(){
    try {
      var exp = experimentFromCookie();
      var key = 'clawea-variant-impression:' + window.location.pathname + ':' + exp.variantId;
      if (sessionStorage.getItem(key)) return;
      sessionStorage.setItem(key, '1');
      track('variant_assignment', { actionOutcome: 'impression' });
    } catch {}
  }

  function hydrateLeadForms(){
    var forms = document.querySelectorAll('[data-lead-form]');
    if (!forms.length) return;

    forms.forEach(function(form){
      if (!(form instanceof HTMLFormElement)) return;
      var statusEl = form.querySelector('[data-lead-form-status]');

      form.addEventListener('submit', async function(e){
        e.preventDefault();

        var fd = new FormData(form);
        var idempotencyKey = 'lead_' + Math.random().toString(36).slice(2) + Date.now().toString(36);

        var assessment = {
          readinessScore: Number(fd.get('assessment.readinessScore') || 0),
          roiScore: Number(fd.get('assessment.roiScore') || 0),
          riskScore: Number(fd.get('assessment.riskScore') || 0),
          confidenceLabel: clip(String(fd.get('assessment.confidenceLabel') || ''), 80),
        };

        var attribution = currentAttribution();
        var payload = {
          fullName: clip(String(fd.get('fullName') || ''), 120),
          email: clip(String(fd.get('email') || ''), 200),
          company: clip(String(fd.get('company') || ''), 160),
          role: clip(String(fd.get('role') || ''), 120),
          teamSize: clip(String(fd.get('teamSize') || ''), 80),
          timeline: clip(String(fd.get('timeline') || ''), 120),
          primaryUseCase: clip(String(fd.get('primaryUseCase') || ''), 600),
          intentNote: clip(String(fd.get('intentNote') || ''), 1200),
          page: window.location.pathname,
          pageFamily: derivePageFamily(window.location.pathname),
          attribution: attribution,
          firstTouch: {
            ts: attribution.first_touch_ts,
            path: attribution.first_touch_path,
            pageFamily: attribution.first_touch_page_family,
            source: attribution.source,
          },
          assessment: assessment,
          idempotencyKey: idempotencyKey,
          turnstileToken: clip(String(fd.get('cf-turnstile-response') || ''), 3000),
        };

        if (statusEl) statusEl.textContent = 'Submitting...';

        try {
          var res = await fetch(LEAD_ENDPOINT, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(payload),
          });
          var out = await res.json();

          if (!res.ok || !out || out.ok !== true) {
            if (statusEl) statusEl.textContent = 'Submission failed. Please check your inputs and try again.';
            track('contact_intent_submit', { actionOutcome: 'failed', ctaId: form.getAttribute('data-cta') || 'lead-form' });
            return;
          }

          if (statusEl) {
            statusEl.textContent = out.deduped
              ? 'Thanks. We already have your brief and will follow up shortly.'
              : 'Thanks. Your brief is in queue. We will reach out soon.';
          }

          track('lead_submit', {
            actionOutcome: out.deduped ? 'deduped' : 'submitted',
            ctaId: form.getAttribute('data-cta') || 'lead-form',
            ctaVariant: experimentFromCookie().ctaVariant,
          });
        } catch {
          if (statusEl) statusEl.textContent = 'Submission failed. Please try again.';
          track('contact_intent_submit', { actionOutcome: 'network_error', ctaId: form.getAttribute('data-cta') || 'lead-form' });
        }
      });
    });
  }

  captureAttribution();
  applyVariantCopy();
  markVariantImpression();
  hydrateLeadForms();

  document.querySelectorAll("a[href]").forEach(function(el){
    const hrefAttr = clip(el.getAttribute("href"), 600);
    if (!hrefAttr) return;

    const isMailto = hrefAttr.toLowerCase().startsWith("mailto:");
    const isCta = Boolean(el.classList.contains("cta-btn") || el.getAttribute("data-cta"));

    if (isCta && hrefAttr.startsWith("/")) {
      el.setAttribute("href", appendAttributionToHref(hrefAttr));
    }

    if (!isCta && !isMailto) return;

    el.addEventListener("click", function(){
      const href = clip(el.getAttribute("href"), 600);
      const ctaId = clip(el.getAttribute("data-cta") || el.textContent || "cta", 120);
      const ctaVariant = clip(
        el.getAttribute("data-cta-variant")
          || (el.classList.contains("cta-btn-outline") ? "outline" : "primary"),
        80,
      );

      if (href && href.toLowerCase().startsWith("mailto:")) {
        track("contact_email_click", { href, ctaId, ctaVariant, actionOutcome: "clicked" });
      } else {
        track("cta_click", { href, ctaId, ctaVariant, actionOutcome: "clicked", targetPath: href && href.startsWith('/') ? href.split('?')[0] : undefined });
      }
    }, { passive: true });
  });

  if (INTENT_PATHS.has(window.location.pathname)) {
    track("contact_intent_view", {
      ctaId: window.location.pathname,
      ctaVariant: experimentFromCookie().ctaVariant,
      actionOutcome: "view",
    });
  }
})();
</script>`;
}

function nav(currentPath: string): string {
  const links = [
    { href: "/controls", label: "Controls" },
    { href: "/workflows", label: "Workflows" },
    { href: "/tools", label: "Tools" },
    { href: "/channels", label: "Channels" },
    { href: "/trust", label: "Trust" },
    { href: "/pricing", label: "Pricing" },
    { href: "/assessment", label: "Assessment" },
  ];
  const linkHtml = links
    .map((l) => {
      const active = currentPath === l.href || currentPath.startsWith(l.href + "/");
      return `<a href="${l.href}"${active ? ' aria-current="page"' : ''}>${l.label}</a>`;
    })
    .join("");

  return `
  <nav aria-label="Main navigation">
    <div class="wrap">
      <a href="/" class="logo" aria-label="Claw EA home">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
          <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
        </svg>
        claw<span>ea</span>
      </a>
      <form class="nav-search" role="search" action="/glossary" method="get" aria-label="Search glossary and guides">
        <label for="nav-search-input" class="sr-only">Search glossary and guides</label>
        <span class="nav-search-icon" aria-hidden="true">⌕</span>
        <input
          id="nav-search-input"
          name="q"
          type="search"
          data-global-search
          placeholder="Search playbooks"
          autocapitalize="off"
          autocomplete="off"
          spellcheck="false"
          enterkeyhint="search"
          aria-autocomplete="list"
          aria-controls="nav-search-results"
        >
        <button type="button" class="nav-search-clear" data-search-clear aria-label="Clear search" hidden>×</button>
        <span class="nav-search-hint" aria-hidden="true">/</span>
        <div class="nav-search-results" id="nav-search-results" data-search-results role="listbox" hidden></div>
      </form>
      <button class="nav-toggle" aria-expanded="false" aria-controls="nav-menu" aria-label="Toggle navigation">
        <span></span><span></span><span></span>
      </button>
      <div class="links" id="nav-menu">
        ${linkHtml}
        <a href="/contact" class="cta-btn" data-cta="nav-contact" data-cta-copy data-cta-proof="Talk to Sales" data-cta-roi="Run assessment" data-cta-speed="Start assessment">Talk to Sales</a>
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
          <li><a href="/sources">Source Hub</a></li>
          <li><a href="/assessment">Assessment</a></li>
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
