#!/usr/bin/env node
import { readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { signMessage } from "../../../skill-did-work/dist/signing.js";

const message = process.argv.slice(2).join(" ").trim();

if (!message) {
  console.error("Usage: sign-message \"<message>\"");
  process.exit(1);
}

const passphraseFromEnv = process.env.DID_WORK_PASSPHRASE?.trim();
const passphrasePath = path.join(os.homedir(), ".openclaw", "did-work", "identity", "passphrase.txt");

let passphrase = passphraseFromEnv;
if (!passphrase) {
  try {
    passphrase = readFileSync(passphrasePath, "utf8").trim();
  } catch (err) {
    console.error("Passphrase missing. Set DID_WORK_PASSPHRASE or create:", passphrasePath);
    process.exit(1);
  }
}

if (!passphrase) {
  console.error("Passphrase is empty. Refusing to sign.");
  process.exit(1);
}

const envelope = await signMessage(message, passphrase);
process.stdout.write(`${JSON.stringify(envelope, null, 2)}\n`);
