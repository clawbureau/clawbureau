#!/usr/bin/env npx tsx
import * as fs from "node:fs";
import * as path from "node:path";
import { chromium } from "playwright";

const args = process.argv.slice(2);
const getArg = (name: string): string | undefined => {
  const idx = args.indexOf(`--${name}`);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : undefined;
};

const base = (getArg("base") ?? process.env.CLAWEA_BASE_URL ?? "https://www.clawea.com").replace(/\/+$/, "");
const outDir = path.resolve(
  getArg("output") ?? path.resolve(import.meta.dirname ?? ".", "../../artifacts/ops/clawea-www/ux-capture"),
);
const waitMs = Math.max(500, Math.min(10_000, Number(getArg("wait-ms") ?? "2200")));

const pages = [
  "/",
  "/pricing",
  "/trust",
  "/contact",
  "/assessment",
  "/assessment/result",
  "/book",
  "/sources",
];

const desktop = { name: "desktop", width: 1440, height: 1024 };
const mobile = { name: "mobile", width: 390, height: 844 };
const viewports = [desktop, mobile];

function slugFor(route: string): string {
  if (route === "/") return "home";
  return route.replace(/^\/+/, "").replace(/\/+$/g, "").replace(/\//g, "__");
}

async function main(): Promise<void> {
  fs.mkdirSync(outDir, { recursive: true });

  const browser = await chromium.launch({ headless: true });
  const manifest: Array<Record<string, unknown>> = [];

  try {
    for (const route of pages) {
      const url = `${base}${route}`;
      const slug = slugFor(route);

      for (const viewport of viewports) {
        const page = await browser.newPage({ viewport: { width: viewport.width, height: viewport.height } });
        try {
          await page.goto(url, { waitUntil: "domcontentloaded", timeout: 90_000 });
          await page.waitForTimeout(waitMs);

          const abovePath = path.join(outDir, `${slug}__${viewport.name}__above.png`);
          const fullPath = path.join(outDir, `${slug}__${viewport.name}__full.png`);

          await page.screenshot({ path: abovePath, fullPage: false });
          await page.screenshot({ path: fullPath, fullPage: true });

          manifest.push({
            route,
            url,
            viewport: viewport.name,
            files: {
              above: path.relative(outDir, abovePath),
              full: path.relative(outDir, fullPath),
            },
          });
        } finally {
          await page.close();
        }
      }
    }
  } finally {
    await browser.close();
  }

  const manifestPath = path.join(outDir, "manifest.json");
  fs.writeFileSync(
    manifestPath,
    JSON.stringify(
      {
        generatedAt: new Date().toISOString(),
        base,
        pages,
        viewports: viewports.map((v) => ({ name: v.name, width: v.width, height: v.height })),
        captures: manifest,
      },
      null,
      2,
    ),
  );

  console.log(`Captured screenshots: ${manifest.length * 2} files`);
  console.log(`Manifest: ${manifestPath}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
