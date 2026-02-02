#!/usr/bin/env node
import { readFileSync, existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const message = process.argv.slice(2).join(" ").trim();

if (!message) {
  console.error('Usage: sign-message "<message>"');
  process.exit(1);
}

const passphraseFromEnv = process.env.DID_WORK_PASSPHRASE?.trim();
const passphrasePath = path.join(os.homedir(), ".openclaw", "did-work", "identity", "passphrase.txt");

let passphrase = passphraseFromEnv;
if (!passphrase) {
  try {
    passphrase = readFileSync(passphrasePath, "utf8").trim();
  } catch {
    console.error("Passphrase missing. Set DID_WORK_PASSPHRASE or create:", passphrasePath);
    process.exit(1);
  }
}

if (!passphrase) {
  console.error("Passphrase is empty. Refusing to sign.");
  process.exit(1);
}

const scriptDir = path.dirname(fileURLToPath(import.meta.url));

const findSkillSigningModule = () => {
  // Allow explicit override for unusual layouts
  const override = process.env.DID_WORK_SKILL_SIGNING_PATH?.trim();
  if (override && existsSync(override)) return override;

  // Walk up from this script looking for skill-did-work/dist/signing.js
  let dir = scriptDir;
  for (let i = 0; i < 12; i++) {
    const candidate = path.join(dir, "skill-did-work", "dist", "signing.js");
    if (existsSync(candidate)) return candidate;

    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }

  return null;
};

const signingModulePath = findSkillSigningModule();
if (!signingModulePath) {
  console.error(
    "Could not locate skill-did-work/dist/signing.js. Set DID_WORK_SKILL_SIGNING_PATH to the absolute path, or ensure the repo contains skill-did-work/ at or above this script.",
  );
  process.exit(1);
}

const { signMessage } = await import(pathToFileURL(signingModulePath).href);

const envelope = await signMessage(message, passphrase);
process.stdout.write(`${JSON.stringify(envelope, null, 2)}\n`);
