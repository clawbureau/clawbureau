/**
 * SEO utilities: JSON-LD structured data, meta tags, OG, canonical.
 */

const SITE = "https://www.clawea.com";
const ORG_NAME = "Claw Bureau";
const LOGO_URL = `${SITE}/logo.png`;

export interface PageMeta {
  title: string;
  description: string;
  path: string;
  canonicalPath?: string;
  ogType?: string;
  ogImage?: string;
  ogImageAlt?: string;
  twitterSite?: string;
  articleSection?: string;
  noindex?: boolean;
  publishedTime?: string;
  modifiedTime?: string;
}

function normalizePath(path: string): string {
  let out = (path || "/").trim();
  if (!out.startsWith("/")) out = `/${out}`;
  out = out.replace(/\/+/g, "/");
  if (out.length > 1) out = out.replace(/\/+$/, "");
  return out || "/";
}

export function canonical(path: string): string {
  return `${SITE}${normalizePath(path)}`;
}

export function metaTags(m: PageMeta): string {
  const url = canonical(m.canonicalPath ?? m.path);
  const ogImage = m.ogImage ?? `${SITE}/og-default.png`;
  const ogImageAlt = m.ogImageAlt ?? `${m.title} social preview`;
  const twitterSite = m.twitterSite ?? "@clawbureau";
  // For Plan A index gating: keep long-tail pages noindex but allow discovery via internal links.
  const robots = m.noindex ? "noindex,follow" : "index,follow,max-snippet:-1,max-image-preview:large";
  return `
    <title>${esc(m.title)}</title>
    <meta name="description" content="${esc(m.description)}">
    <meta name="robots" content="${robots}">
    <link rel="canonical" href="${esc(url)}">

    <meta property="og:type" content="${esc(m.ogType ?? "website")}">
    <meta property="og:url" content="${esc(url)}">
    <meta property="og:title" content="${esc(m.title)}">
    <meta property="og:description" content="${esc(m.description)}">
    <meta property="og:image" content="${esc(ogImage)}">
    <meta property="og:image:alt" content="${esc(ogImageAlt)}">
    <meta property="og:image:width" content="1200">
    <meta property="og:image:height" content="630">
    <meta property="og:site_name" content="${esc(ORG_NAME)}">
    <meta property="og:locale" content="en_US">

    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:site" content="${esc(twitterSite)}">
    <meta name="twitter:url" content="${esc(url)}">
    <meta name="twitter:title" content="${esc(m.title)}">
    <meta name="twitter:description" content="${esc(m.description)}">
    <meta name="twitter:image" content="${esc(ogImage)}">
    <meta name="twitter:image:alt" content="${esc(ogImageAlt)}">

    ${m.articleSection ? `<meta property="article:section" content="${esc(m.articleSection)}">` : ""}
    ${m.publishedTime ? `<meta property="article:published_time" content="${esc(m.publishedTime)}">` : ""}
    ${m.modifiedTime ? `<meta property="article:modified_time" content="${esc(m.modifiedTime)}">` : ""}
  `;
}

/* ── JSON-LD Schemas ──────────────────────────────────────────── */

export function orgSchema(): string {
  return jsonLd({
    "@type": "Organization",
    name: ORG_NAME,
    url: SITE,
    logo: LOGO_URL,
    sameAs: [
      "https://github.com/clawbureau",
      "https://twitter.com/clawbureau",
    ],
    contactPoint: {
      "@type": "ContactPoint",
      contactType: "sales",
      email: "enterprise@clawbureau.com",
      url: `${SITE}/contact`,
    },
  });
}

export function websiteSchema(): string {
  return jsonLd({
    "@type": "WebSite",
    name: "Claw Enterprise Agents",
    url: SITE,
    potentialAction: {
      "@type": "SearchAction",
      target: `${SITE}/glossary?q={search_term_string}`,
      "query-input": "required name=search_term_string",
    },
  });
}

export function breadcrumbSchema(items: { name: string; url: string }[]): string {
  return jsonLd({
    "@type": "BreadcrumbList",
    itemListElement: items.map((item, i) => ({
      "@type": "ListItem",
      position: i + 1,
      name: item.name,
      item: item.url,
    })),
  });
}

export function faqSchema(faqs: { q: string; a: string }[]): string {
  return jsonLd({
    "@type": "FAQPage",
    mainEntity: faqs.map((f) => ({
      "@type": "Question",
      name: f.q,
      acceptedAnswer: {
        "@type": "Answer",
        text: f.a,
      },
    })),
  });
}

export function howToSchema(
  howTo: { title: string; steps: Array<{ name: string; text: string }> },
  url: string,
): string {
  return jsonLd({
    "@type": "HowTo",
    name: howTo.title,
    url,
    step: howTo.steps.map((s) => ({
      "@type": "HowToStep",
      name: s.name,
      text: s.text,
    })),
  });
}

export function serviceSchema(name: string, description: string, url: string): string {
  return jsonLd({
    "@type": "Service",
    name,
    description,
    url,
    provider: {
      "@type": "Organization",
      name: ORG_NAME,
      url: SITE,
    },
    areaServed: "Worldwide",
    serviceType: "Enterprise AI Agent Infrastructure",
  });
}

export function productSchema(
  name: string,
  description: string,
  url: string,
  offers?: { price: string; priceCurrency: string }[],
): string {
  return jsonLd({
    "@type": "Product",
    name,
    description,
    url,
    brand: { "@type": "Brand", name: ORG_NAME },
    ...(offers?.length
      ? {
          offers: offers.map((o) => ({
            "@type": "Offer",
            price: o.price,
            priceCurrency: o.priceCurrency,
            availability: "https://schema.org/InStock",
          })),
        }
      : {}),
  });
}

export function definedTermSchema(term: string, definition: string, url: string): string {
  return jsonLd({
    "@type": "DefinedTerm",
    name: term,
    description: definition,
    url,
    inDefinedTermSet: {
      "@type": "DefinedTermSet",
      name: "Claw Bureau Enterprise Glossary",
      url: `${SITE}/glossary`,
    },
  });
}

export function techArticleSchema(opts: {
  headline: string;
  description: string;
  url: string;
  datePublished?: string;
  dateModified?: string;
  section?: string;
}): string {
  return jsonLd({
    "@type": "TechArticle",
    headline: opts.headline,
    description: opts.description,
    url: opts.url,
    mainEntityOfPage: opts.url,
    datePublished: opts.datePublished,
    dateModified: opts.dateModified ?? opts.datePublished,
    articleSection: opts.section,
    author: {
      "@type": "Organization",
      name: ORG_NAME,
      url: SITE,
    },
    publisher: {
      "@type": "Organization",
      name: ORG_NAME,
      url: SITE,
      logo: {
        "@type": "ImageObject",
        url: LOGO_URL,
      },
    },
  });
}

function jsonLd(data: Record<string, unknown>): string {
  const obj = { "@context": "https://schema.org", ...data };
  return `<script type="application/ld+json">${JSON.stringify(obj)}</script>`;
}

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
