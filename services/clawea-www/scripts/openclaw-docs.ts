/**
 * Official OpenClaw docs helpers.
 *
 * Canonical docs source: openclaw-ref (a git checkout of github.com/openclaw/openclaw)
 * Path: /Users/gfw/clawd/02-Projects/clawbureau/openclaw-ref/docs
 *
 * Deepwiki docs are supplemental (better code understanding, not canonical).
 * Path: /Users/gfw/clawd/clawbureau/docs/openclaw
 */

import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";

export interface DocExcerpt {
  label: string;
  source: "official" | "deepwiki";
  filePath: string;
  excerpt: string;
  /** Public, citable URL when available (official docs/code). */
  canonicalUrl?: string;
  /** Optional line anchors for code citations (to mimic deepwiki-style references). */
  startLine?: number;
  endLine?: number;
}

export const OPENCLAW_REF_ROOT = "/Users/gfw/clawd/02-Projects/clawbureau/openclaw-ref";
export const OFFICIAL_DOCS_ROOT = path.join(OPENCLAW_REF_ROOT, "docs");

export const OPENCLAW_GITHUB_REF = (() => {
  if (process.env.OPENCLAW_GITHUB_REF) return process.env.OPENCLAW_GITHUB_REF;
  try {
    const sha = execSync("git rev-parse HEAD", {
      cwd: OPENCLAW_REF_ROOT,
      stdio: ["ignore", "pipe", "ignore"],
    })
      .toString()
      .trim();
    return sha || "main";
  } catch {
    return "main";
  }
})();

export const OPENCLAW_GITHUB_BLOB_BASE = `https://github.com/openclaw/openclaw/blob/${OPENCLAW_GITHUB_REF}`;

export const DEEPWIKI_ROOT = "/Users/gfw/clawd/clawbureau/docs/openclaw";

export function hasOpenClawRef(): boolean {
  return fs.existsSync(OFFICIAL_DOCS_ROOT);
}

export function hasDeepWiki(): boolean {
  return fs.existsSync(DEEPWIKI_ROOT);
}

export function readExcerpt(filePath: string, maxChars = 4000): string {
  const full = fs.readFileSync(filePath, "utf-8").replace(/\r\n/g, "\n");

  // Strip YAML frontmatter to keep tokens low
  const cleaned = full.startsWith("---")
    ? full.replace(/^---[\s\S]*?---\n/, "")
    : full;

  return cleaned.trim().slice(0, maxChars);
}

export function readExcerptAround(
  filePath: string,
  matcher: RegExp,
  opts: { before?: number; after?: number; maxChars?: number } = {},
): { excerpt: string; startLine: number; endLine: number } | null {
  const full = fs.readFileSync(filePath, "utf-8").replace(/\r\n/g, "\n");
  const lines = full.split("\n");

  // Ensure we don't get bitten by global regex state.
  const rx = new RegExp(matcher.source, matcher.flags.replace(/g/g, ""));
  const idx = lines.findIndex((l) => rx.test(l));
  if (idx === -1) return null;

  const before = opts.before ?? 8;
  const after = opts.after ?? 32;
  const start = Math.max(0, idx - before);
  const end = Math.min(lines.length, idx + after);

  const maxChars = opts.maxChars ?? 4500;
  const excerpt = lines.slice(start, end).join("\n").trim().slice(0, maxChars);

  return { excerpt, startLine: start + 1, endLine: end };
}

export function officialRepoFile(rel: string, label?: string, maxChars = 4500): DocExcerpt | null {
  const fp = path.join(OPENCLAW_REF_ROOT, rel);
  if (!fs.existsSync(fp)) return null;
  return {
    label: label ?? `OpenClaw source: ${rel}`,
    source: "official",
    filePath: fp,
    canonicalUrl: `${OPENCLAW_GITHUB_BLOB_BASE}/${rel}`,
    excerpt: readExcerpt(fp, maxChars),
  };
}

export function officialRepoSnippet(
  rel: string,
  matcher: RegExp,
  label?: string,
  opts: { before?: number; after?: number; maxChars?: number } = {},
): DocExcerpt | null {
  const fp = path.join(OPENCLAW_REF_ROOT, rel);
  if (!fs.existsSync(fp)) return null;

  const around = readExcerptAround(fp, matcher, opts);
  if (around) {
    const { excerpt, startLine, endLine } = around;
    return {
      label: label ?? `OpenClaw source: ${rel}`,
      source: "official",
      filePath: fp,
      canonicalUrl: `${OPENCLAW_GITHUB_BLOB_BASE}/${rel}#L${startLine}-L${endLine}`,
      excerpt,
      startLine,
      endLine,
    };
  }

  return {
    label: label ?? `OpenClaw source: ${rel}`,
    source: "official",
    filePath: fp,
    canonicalUrl: `${OPENCLAW_GITHUB_BLOB_BASE}/${rel}`,
    excerpt: readExcerpt(fp, opts.maxChars ?? 4500),
  };
}

export function officialDoc(rel: string, label?: string, maxChars = 4500): DocExcerpt | null {
  const fp = path.join(OFFICIAL_DOCS_ROOT, rel);
  if (!fs.existsSync(fp)) return null;
  return {
    label: label ?? `OpenClaw official docs: ${rel}`,
    source: "official",
    filePath: fp,
    canonicalUrl: `${OPENCLAW_GITHUB_BLOB_BASE}/docs/${rel}`,
    excerpt: readExcerpt(fp, maxChars),
  };
}

export function deepwikiDoc(fileName: string, label: string, maxChars = 3500): DocExcerpt | null {
  const fp = path.join(DEEPWIKI_ROOT, fileName);
  if (!fs.existsSync(fp)) return null;
  return {
    label,
    source: "deepwiki",
    filePath: fp,
    excerpt: readExcerpt(fp, maxChars),
  };
}

export function officialChannelDoc(channelSlug: string): DocExcerpt | null {
  const map: Record<string, string> = {
    slack: "channels/slack.md",
    discord: "channels/discord.md",
    telegram: "channels/telegram.md",
    whatsapp: "channels/whatsapp.md",
    signal: "channels/signal.md",
    matrix: "channels/matrix.md",
    email: "channels/email.md",
    "google-chat": "channels/googlechat.md",
    mattermost: "channels/mattermost.md",
    imessage: "channels/imessage.md",
    "microsoft-teams": "channels/msteams.md",
    // fallback: other channel docs exist but we only map major ones here
  };

  const rel = map[channelSlug];
  return rel ? officialDoc(rel) : null;
}

export function officialProviderDoc(providerSlug: string): DocExcerpt | null {
  const map: Record<string, string> = {
    anthropic: "providers/anthropic.md",
    openai: "providers/openai.md",
    openrouter: "providers/openrouter.md",
    ollama: "providers/ollama.md",
    bedrock: "providers/bedrock.md",
    // google gemini is covered under providers/models.md currently
    google: "providers/models.md",
  };

  const rel = map[providerSlug];
  return rel ? officialDoc(rel) : null;
}

export function officialChannelCode(channelSlug: string): DocExcerpt[] {
  const map: Record<string, Array<{ rel: string; matcher: RegExp; label: string }>> = {
    discord: [
      {
        rel: "src/discord/monitor/allow-list.ts",
        matcher: /export function resolveDiscordChannelConfig/,
        label: "OpenClaw source: Discord channel config resolution",
      },
      {
        rel: "src/discord/monitor/allow-list.ts",
        matcher: /export function resolveDiscordShouldRequireMention/,
        label: "OpenClaw source: Discord mention gating defaults",
      },
    ],
    slack: [
      {
        rel: "src/slack/monitor/channel-config.ts",
        matcher: /export function resolveSlackChannelConfig/,
        label: "OpenClaw source: Slack channel config resolution",
      },
    ],
  };

  const entries = map[channelSlug] ?? [];
  const excerpts: DocExcerpt[] = [];
  for (const e of entries) {
    const ex = officialRepoSnippet(e.rel, e.matcher, e.label, {
      before: 6,
      after: 70,
      maxChars: 3500,
    });
    if (ex) excerpts.push(ex);
  }
  return excerpts;
}

export function officialChannelSources(channelSlug: string): DocExcerpt[] {
  const out: DocExcerpt[] = [];
  const doc = officialChannelDoc(channelSlug);
  if (doc) out.push(doc);
  out.push(...officialChannelCode(channelSlug));
  return out;
}
