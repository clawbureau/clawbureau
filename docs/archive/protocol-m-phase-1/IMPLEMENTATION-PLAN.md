# Protocol M Implementation Plan (OpenClaw Skill)

**Generated:** 2026-01-31 via Oracle GPT-5.2 Pro
**Approach:** Build as ClawHub-published skill (not core PR)
**Timeline:** 6 milestones, ~28 days to v1.0.0

---

Below is a production-ready implementation plan for **Protocol M as a ClawHub-published OpenClaw skill** (not a core PR), aligned to the normative spec and CLI contract in **`02-Projects/protocol-m/PRD-phase-1.md`** and the authoritative interop gate in **`02-Projects/protocol-m/golden-vector.json`**.

Referenced source files:
- Spec + CLI contract + exit codes + rotation cert: **`02-Projects/protocol-m/PRD-phase-1.md`**
- Context/revised direction: **`02-Projects/protocol-m/REVISED-SCOPE.md`**
- Authoritative golden vector: **`02-Projects/protocol-m/golden-vector.json`**
- Moltbook platform intent/context: **`02-Projects/protocol-m/moltbook-application-REVISED.md`**

---

## 1) File Structure (complete skill directory layout)

Skill slug: `protocol-m`
Package name: `@clawhub/protocol-m` (or `@openclaw-skill/protocol-m` depending on ClawHub conventions)

```text
protocol-m/
  SKILL.md
  skill.json                          # tool/command manifest for OpenClaw (skill runtime)
  package.json
  pnpm-lock.yaml                      # or package-lock.json (pick one)
  tsconfig.json
  eslint.config.mjs                   # optional but recommended
  vitest.config.ts
  LICENSE
  CHANGELOG.md

  bin/
    protocol-m.mjs                    # Node CLI entry (invoked by OpenClaw tool runner)
    protocol-m.sh                     # thin wrapper for environments that prefer shell

  src/
    index.ts                          # exports library API for other skills/tools
    constants.ts                      # schema versions, exit codes, limits
    errors.ts                         # typed errors -> exit codes
    util/
      bytes.ts
      time.ts
      fs.ts
      json.ts

    crypto/
      ed25519.ts                      # @noble/ed25519 wrapper
      sha256.ts                       # sha256 helpers
      jcs.ts                          # RFC8785 canonicalization wrapper
      base58btc.ts                    # base58btc helpers

    did/
      didKey.ts                       # did:key derive + parse (multicodec 0xed01)

    envelope/
      types.ts                        # TS types
      schema.ts                       # zod schemas + strict validation
      artifactEnvelope.ts             # create/verify artifact envelope
      message.ts                      # domain-separated message signing for Moltbook
      rotation.ts                     # rotation certificate create/verify

    identity/
      identityTypes.ts                # IdentityState / IdentityMetadata types
      identityPaths.ts                # default dirs + env overrides
      identityStore.ts                # load/save identity.json
      keyStore.ts                     # encrypted key storage (age passphrase)
      identity.ts                     # init/show/loadActive/rotate

    moltbook/
      moltbookClient.ts               # HTTP client for challenge/bind (optional)
      moltbookWorkflows.ts            # higher-level flows: bind, sign-post

    cli/
      main.ts                         # argument parsing, command routing
      commands/
        identityInit.ts
        identityShow.ts
        identityRotate.ts
        signArtifact.ts
        verifyArtifact.ts
        signMessage.ts
        verifyMessage.ts
        manifestExport.ts
        moltbookChallenge.ts          # optional convenience
        moltbookBind.ts               # optional convenience

  prompts/
    moltbook-bind.md
    sign-artifact.md
    rotate-identity.md
    troubleshooting.md

  fixtures/
    golden-vector.json                # copied from 02-Projects/protocol-m/golden-vector.json
    readme-example-envelope.json
    invalid-envelopes/
      bad-version.json
      bad-did.json
      bad-hash.json

  tests/
    golden.test.ts
    didKey.test.ts
    jcs.test.ts
    envelopeArtifact.test.ts
    messageSigning.test.ts
    rotation.test.ts
    keystore.test.ts
    permissions.test.ts
    perf.verify.bench.test.ts         # optional "budget" test (non-flaky)

  scripts/
    prepublish-check.mjs              # validates fixtures present, builds, runs golden
    release.mjs                       # optional

  .github/
    workflows/
      ci.yml                          # run tests on linux/mac/windows
```

Notes:
- `fixtures/golden-vector.json` MUST be byte-for-byte aligned with **`02-Projects/protocol-m/golden-vector.json`**.
- `skill.json` is included to make the skill "installable + tool-exposable" without requiring OpenClaw core changes.

---

## 2) `SKILL.md` (draft)

```md
# Protocol M (protocol-m)

Protocol M is an OpenClaw skill that gives agents a **portable cryptographic identity** (`did:key`) and the ability to **sign and verify** messages and artifacts using **Ed25519** with **deterministic canonical JSON (RFC 8785 JCS)**.

It is designed to enable "instant verification" workflows on Moltbook (challenge-response DID binding + signed posts).

## When to use this skill

Use Protocol M when you need:

- A **permanent cryptographic identity** for an agent or operator (portable across machines/channels)
- **Offline-verifiable** signatures on files/artifacts
- **Moltbook identity binding** via challenge-response signatures
- **Key rotation** with cryptographic continuity (rotation certificates)

Do not use it for:
- Blockchain settlement
- Access-control / delegation (out of scope for v1)
- Encrypting message content (this skill focuses on signing + identity)

## Capabilities

### Identity
- Generate an Ed25519 keypair and derive `did:key` (multicodec `0xed01`, base58btc multibase `z`)
- Store private key encrypted-at-rest (no plaintext key on disk)
- Enforce safe filesystem permissions where possible (fail-closed on Unix)

### Artifact signing (schema `m1`)
- Create signature envelopes for files/artifacts:
  - sha256(file bytes)
  - RFC8785 canonical JSON
  - Ed25519 signature over canonical bytes

### Message signing (Moltbook binding)
- Domain-separated challenge signing:
  - signs bytes of: `moltbook:bind:v1:<challenge>`

### Key rotation
- Create and verify rotation certificates (`did_rotation`) signed by both old and new keys.

## Commands (Tools)

- `identity init` / `identity show` / `identity rotate`
- `sign <file>` / `verify <file> <sig.json>`
- `sign-message "<text>"` / `verify-message "<text>" "<sig>" "<did>"`
- `manifest export`

## Output formats and compatibility

Protocol M is gated by a golden vector for cross-implementation compatibility.
Any change that breaks deterministic bytes/canonicalization is considered breaking.

## Security notes

- Protect your passphrase.
- Post edits invalidate signatures.
- Rotation certificates should be stored/backuped alongside identity metadata.

## License
MIT
```

---

## 3) CLI Commands (spec + flags + exit codes)

The skill provides a Node CLI (`bin/protocol-m.mjs`). OpenClaw will call it via tool execution; it can also be run directly.

### Command surface (matches PRD, skill-wrapped)

From **`02-Projects/protocol-m/PRD-phase-1.md`** §6.

#### `protocol-m identity init`
```bash
protocol-m identity init [--force] [--identity-path <path>] [--passphrase-stdin]
```
Behavior:
- Creates identity directory (default `~/.openclaw/identity/`)
- Generates Ed25519 keypair
- Derives did:key
- Encrypts private key to `root.key.enc` (age passphrase mode)
- Writes:
  - `identity.json`
  - `root.pub` (hex)
- Enforces perms:
  - dir `0700`, key `0600` (Unix) else exit code `6`.

Output (human):
- prints DID + identity path
Output (`--json` optional enhancement):
```json
{ "did": "did:key:...", "identityPath": "...", "createdAt": "..." }
```

#### `protocol-m identity show`
```bash
protocol-m identity show [--identity-path <path>] [--json]
```
- Prints active DID and paths.
- Exit `3` if missing.

#### `protocol-m identity rotate`
```bash
protocol-m identity rotate [--identity-path <path>] [--reason <text>] [--output <path>] [--json]
```
- Loads current identity (prompts for passphrase unless `--passphrase-stdin`)
- Generates new keypair, new did:key
- Creates rotation certificate (type `did_rotation`, schema `m1`) signed by both keys
- Writes new encrypted key to `root.key.enc` (or versioned filenames, see below)
- Updates `identity.json` history
- Writes rotation cert to `rotation-<timestamp>.json` (or `--output`)
- Prints new DID and cert path

**Key file versioning recommendation (production):**
- Keep `keys/`:
  - `keys/<did>.key.enc`
  - `keys/<did>.pub`
- `identity.json` points to active DID and active key path.
This prevents accidental loss during rotation.

#### `protocol-m sign <file>`
```bash
protocol-m sign <file> [--meta key=value ...] [--output <path>] [--dry-run] [--identity-path <path>]
```
- Reads file bytes
- Builds `artifact_signature` envelope `m1`
- `artifact.name` defaults to basename(file)
- `createdAt` = now UTC RFC3339
- `metadata`: sorted keys (canonicalization handles determinism)
- Writes envelope JSON to `<file>.sig.json` unless `--output`

#### `protocol-m verify <file> <sig.json>`
```bash
protocol-m verify <file> <sig.json> [--json]
```
- Strict-validate envelope schema
- Recompute sha256(file)
- Extract pubkey from did:key
- Verify Ed25519 signature over RFC8785 canonical bytes
- Exit codes (stable contract from PRD):
  - `0` success
  - `4` hash mismatch
  - `5` signature invalid
  - `7` invalid DID/decode failure

#### `protocol-m sign-message "<text>"`
```bash
protocol-m sign-message "<text>" [--domain moltbook-bind-v1] [--identity-path <path>]
```
- Domain-separated signing.
- For Moltbook binding (default): signs UTF-8 bytes of:
  - `moltbook:bind:v1:<text>`
- Prints base64 signature only (easy paste).

#### `protocol-m verify-message "<text>" "<sig_b64>" "<did>"`
```bash
protocol-m verify-message "<text>" "<sig_b64>" "<did>" [--domain moltbook-bind-v1]
```
- Verifies the same domain-separated bytes.
- Exit `5` if invalid sig, `7` if DID decode failure.

#### `protocol-m manifest export`
```bash
protocol-m manifest export [--identity-path <path>] [--output <path>]
```
- Exports list of known signed artifacts (append-only log recommended).
- If you don't want local indexing in v1, implement as:
  - scans `signatures/` directory and outputs a JSON list.

---

## 4) Core Libraries (TypeScript modules, APIs, and code structure)

All library entrypoints are exported from `src/index.ts` so other skills (or Moltbook integration code) can import without spawning the CLI.

### Constants and exit codes

`src/constants.ts`
```ts
export const PROTOCOL_M_VERSION = "m1" as const;

export const EXIT = {
  OK: 0,
  IDENTITY_MISSING: 3,
  HASH_MISMATCH: 4,
  SIG_INVALID: 5,
  INSECURE_PERMS: 6,
  DID_DECODE_FAILED: 7,
  ROTATION_INVALID: 8,
} as const;

export const LIMITS = {
  ENVELOPE_MAX_BYTES: 32 * 1024, // aligns PRD "cap envelope size"
} as const;
```

### DID: derive + parse

`src/did/didKey.ts`
```ts
export type DidKey = `did:key:${string}`;

export function didKeyFromEd25519Pubkey(pubkey32: Uint8Array): DidKey;

export function ed25519PubkeyFromDidKey(did: string): Uint8Array; // throws DidDecodeError

export function isDidKey(did: string): did is DidKey;
```

Implementation details (must match **`02-Projects/protocol-m/PRD-phase-1.md`** §4.1):
- Prefix bytes: `0xed01` (two bytes: `0xed, 0x01`)
- Multibase base58btc with leading `z`
- DID string: `"did:key:z" + base58btc(prefix||pubkey)`

Use `multiformats/bases/base58` or equivalent base58btc encoder/decoder.

### JCS canonicalization wrapper

`src/crypto/jcs.ts`
```ts
export function jcsCanonicalize(value: unknown): string;
export function jcsCanonicalBytes(value: unknown): Uint8Array; // utf-8 bytes of canonical string
```

Use `canonicalize` npm package (RFC8785). Golden vector requires exact string match.

### Envelope schema (zod strict)

`src/envelope/schema.ts`
```ts
import { z } from "zod";

export const HashSchema = z.object({
  algo: z.literal("sha256"),
  value: z.string().regex(/^[0-9a-f]{64}$/),
}).strict();

export const ArtifactSchema = z.object({
  name: z.string().min(1),
  size: z.number().int().nonnegative(),
}).strict();

export const ArtifactEnvelopeSchema = z.object({
  version: z.literal("m1"),
  type: z.literal("artifact_signature"),
  algo: z.literal("ed25519"),
  did: z.string().min(1),
  hash: HashSchema,
  artifact: ArtifactSchema,
  createdAt: z.string(), // validate RFC3339 in code (date parse + endsWith('Z'))
  metadata: z.record(z.any()),
  signature: z.string(), // base64 (allow "" during canonicalization)
}).strict();

export const RotationCertSchema = z.object({
  version: z.literal("m1"),
  type: z.literal("did_rotation"),
  oldDid: z.string(),
  newDid: z.string(),
  createdAt: z.string(),
  reason: z.string(),
  signatureOld: z.string(),
  signatureNew: z.string(),
}).strict();
```

### Artifact signing/verification

`src/envelope/artifactEnvelope.ts`
```ts
export type ArtifactSignatureEnvelope = /* inferred from schema */;

export type CreateArtifactEnvelopeInput = {
  did: string;
  artifactName: string;
  artifactBytes: Uint8Array;
  createdAt?: string;               // default now UTC RFC3339
  metadata?: Record<string, unknown>;
};

export async function createArtifactEnvelope(
  input: CreateArtifactEnvelopeInput,
  signer: (canonicalBytes: Uint8Array) => Promise<Uint8Array> // returns 64-byte signature
): Promise<ArtifactSignatureEnvelope>;

export type VerifyArtifactEnvelopeResult =
  | { ok: true }
  | { ok: false; reason: "hash_mismatch" | "sig_invalid" | "did_decode_failed" | "schema_invalid" };

export async function verifyArtifactEnvelope(
  artifactBytes: Uint8Array,
  envelope: unknown
): Promise<VerifyArtifactEnvelopeResult>;
```

Signing algorithm must match **`02-Projects/protocol-m/PRD-phase-1.md`** §4.2:
- compute sha256(file bytes)
- set `signature: ""`
- canonicalize via RFC8785 JCS
- sign canonical UTF-8 bytes
- set signature to base64(sig)

Verification:
- schema validate
- extract signature, blank it, canonicalize
- sha256 compare
- did->pubkey
- verify

### Message signing for Moltbook binding

`src/envelope/message.ts`
```ts
export type MessageDomain = "moltbook-bind-v1";

export function messageBytes(text: string, domain: MessageDomain): Uint8Array;

export async function signMessage(
  text: string,
  domain: MessageDomain,
  signer: (msgBytes: Uint8Array) => Promise<Uint8Array>
): Promise<string>; // base64 signature

export async function verifyMessageSignature(
  text: string,
  sigB64: string,
  did: string,
  domain: MessageDomain
): Promise<{ ok: boolean; reason?: "sig_invalid" | "did_decode_failed" | "bad_sig_encoding" }>;
```

Domain-separated format (from **`02-Projects/protocol-m/PRD-phase-1.md`** §4.3):
- bytes = UTF-8 of: `moltbook:bind:v1:` + `<challenge>`

### Rotation certificates

`src/envelope/rotation.ts`
```ts
export type RotationCertificate = /* schema */;

export type CreateRotationCertInput = {
  oldDid: string;
  newDid: string;
  createdAt?: string;
  reason: string;
};

export async function createRotationCertificate(
  input: CreateRotationCertInput,
  signWithOld: (canonicalBytes: Uint8Array) => Promise<Uint8Array>,
  signWithNew: (canonicalBytes: Uint8Array) => Promise<Uint8Array>
): Promise<RotationCertificate>;

export async function verifyRotationCertificate(
  cert: unknown
): Promise<{ ok: true } | { ok: false; reason: "schema_invalid" | "sig_invalid" | "did_decode_failed" }>;
```

Canonicalization rule (from **`02-Projects/protocol-m/PRD-phase-1.md`** §7):
- Both keys sign the same payload with `signatureOld=""` and `signatureNew=""` during canonicalization.

### Identity + encrypted storage (OpenClaw patterns)

Because this is a skill, implement storage in a way that can later be swapped to OpenClaw's native secret store. Use an interface:

`src/identity/keyStore.ts`
```ts
export type EncryptedKeyRecord = {
  did: string;
  alg: "ed25519";
  enc: "age-passphrase";
  createdAt: string;
  payload: string; // armored age text
};

export interface KeyStore {
  saveEncryptedKey(record: EncryptedKeyRecord): Promise<void>;
  loadEncryptedKey(did: string): Promise<EncryptedKeyRecord>;
  listKeyDids(): Promise<string[]>;
}
```

`src/identity/identity.ts`
```ts
export type IdentityState = {
  version: "m1";
  activeDid: string;
  createdAt: string;
  keys: Array<{ did: string; pubKeyHex: string; encryptedKeyPath: string; createdAt: string; revokedAt?: string }>;
  rotations: Array<{ certPath: string; createdAt: string; oldDid: string; newDid: string }>;
};

export async function identityInit(opts: {
  identityPath?: string;
  force?: boolean;
  passphrase?: string; // if undefined, prompt in CLI layer
}): Promise<{ did: string; identityPath: string }>;

export async function identityShow(opts: { identityPath?: string }): Promise<{
  activeDid: string;
  identityPath: string;
  publicKeyHex: string;
}>;

export async function identityRotate(opts: {
  identityPath?: string;
  reason: string;
  passphrase?: string;
  outputCertPath?: string;
}): Promise<{ oldDid: string; newDid: string; certPath: string }>;

export async function loadActiveSigner(opts: {
  identityPath?: string;
  passphrase?: string;
}): Promise<{ did: string; sign: (bytes: Uint8Array) => Promise<Uint8Array> }>;
```

Encryption choice:
- Use age "passphrase mode" to match the PRD storage requirement in **`02-Projects/protocol-m/PRD-phase-1.md`** §6 ("age passphrase").
- Recommended library: `@47ng/age` (pure JS) or a vetted age implementation.
- Store only encrypted payload; never write raw secret key to disk.

Permissions:
- `identityPaths.ts` should enforce:
  - directory `0700`, key files `0600` on Unix; else throw `InsecurePermissionsError` (maps to exit `6`).

---

## 5) Moltbook Integration (binding + verified posts)

Two layers:

### A) What the skill does (client/operator side)
The skill supports the "5-minute proof" flow from **`02-Projects/protocol-m/PRD-phase-1.md`** §0:

1) Generate DID locally
2) Get Moltbook challenge (user obtains from UI or via API if available)
3) Sign challenge with `sign-message` (domain-separated)
4) Paste signature into Moltbook "Bind" UI
5) Sign post content (as an artifact envelope) and attach envelope JSON

#### Skill tools to implement
- `moltbook challenge` (optional convenience)
  - Calls `POST /v1/identity/challenge`
- `moltbook bind` (optional convenience)
  - Calls `POST /v1/identity/bind` with `{ did, challenge, challengeSignature }`
- `moltbook sign-post`
  - Accepts a text file or stdin, signs bytes as an artifact envelope (hash over exact UTF-8 bytes)
  - Outputs `signatureEnvelope` JSON ready to paste

`src/moltbook/moltbookClient.ts`
```ts
export class MoltbookClient {
  constructor(readonly baseUrl: string, readonly authToken?: string) {}

  async createChallenge(): Promise<{ challenge: string; expiresAt: string }>;
  async bindDid(input: { did: string; challenge: string; challengeSignature: string }): Promise<{ ok: true }>;
}
```

### B) How Moltbook verifies (server side expectations)
The skill must produce bytes/envelopes that match Moltbook verification rules described in **`02-Projects/protocol-m/PRD-phase-1.md`** §8:
- Binding verification checks signature over `moltbook:bind:v1:<challenge>`
- Post verification recomputes sha256 over the exact stored UTF-8 bytes and verifies envelope signature + did binding status
- Rotation: Moltbook accepts continuity if a valid rotation cert is presented (cert verification in `rotation.ts` matches the PRD canonicalization rule)

Practical interoperability guidance (important for "exact stored bytes"):
- Skill should recommend signing a file containing the post body **exactly as submitted** (no extra trailing spaces/newlines unless they will be stored).
- Provide `protocol-m sign --from-stdin --name post.txt` variant (or `moltbook sign-post`) to reduce accidental byte drift.

---

## 6) Test Strategy (golden vector gate + coverage)

### Golden vector (CI gate)
File: `tests/golden.test.ts`
Fixture: `fixtures/golden-vector.json` (must match **`02-Projects/protocol-m/golden-vector.json`**)

Test assertions (must all pass):
1. Deterministically derive pubkey from seed (use noble to get keypair from seed)
2. Derive DID equals fixture `did`
3. Compute sha256(file_bytes_utf8) equals fixture `sha256_hex`
4. Build envelope (signature empty) canonicalize and equal fixture `canonical_jcs`
5. Sign canonical bytes and match fixture `signature_base64` (and optionally `signature_hex`)
6. Verify signature using did:key pubkey extraction

This exactly enforces the steps listed in **`02-Projects/protocol-m/golden-vector.json`** `verification_steps`.

### Additional tests (non-golden)
- `didKey.test.ts`
  - decode(encode(pubkey)) roundtrip
  - invalid prefix handling -> exit code mapping reason
- `jcs.test.ts`
  - property-style tests ensuring key ordering stable
  - snapshot canonical strings for known envelopes
- `envelopeArtifact.test.ts`
  - sign→verify roundtrip
  - tamper tests: flip file byte => hash mismatch (exit `4`)
  - tamper tests: flip sig byte => sig invalid (exit `5`)
  - tamper tests: change did => sig invalid or did decode fail
- `messageSigning.test.ts`
  - ensures domain separation exact prefix `moltbook:bind:v1:`
- `rotation.test.ts`
  - create cert and verify ok
  - modify oldDid/newDid => sig invalid
- `keystore.test.ts`
  - encrypt/decrypt with correct passphrase works
  - wrong passphrase fails without corrupting state
- `permissions.test.ts`
  - Unix-only: creates dir with wrong perms -> fail-closed with exit `6`
- `perf.verify.bench.test.ts` (optional, non-flaky)
  - run verify loop N=1000 and assert average under budget on CI *only as a warning*
  - keep hard performance gate out of CI if it risks flakiness; track via benchmark output

---

## 7) Dependencies (npm packages)

Required:
- `@noble/ed25519` — Ed25519 sign/verify (pure JS)
- `@noble/hashes` — sha256 (+ optionally scrypt/pbkdf2 if you don't use age lib)
- `canonicalize` — RFC 8785 JSON Canonical Serialization (must match golden)
- `multiformats` — base58btc (recommended for correctness/interop)
- `zod` — strict schema validation (fail-closed)

Encrypted storage (pick one approach):
- Preferred: `@47ng/age` (age encryption in JS, passphrase mode)
  - If not acceptable, implement passphrase-based encryption using WebCrypto + scrypt from `@noble/hashes/scrypt`, but that deviates from "age passphrase" wording in the PRD.

CLI/runtime:
- `yargs` or `commander` — CLI argument parsing
- `prompts` — passphrase prompt (TTY), plus `--passphrase-stdin` for automation
- `picocolors` — colored output (optional)

Dev/test:
- `typescript`
- `vitest`
- `eslint` (optional)
- `tsx` (optional for local dev)

---

## 8) Installation Flow (ClawHub → first use)

### Install
From OpenClaw:
```bash
/clawhub install protocol-m
```
(or equivalently if OpenClaw exposes a CLI wrapper)
```bash
openclaw clawhub install protocol-m
```

### Verify install (skill tools available)
```bash
openclaw tools list | grep protocol-m
```

### Initialize identity
Either run via tool invocation (preferred in OpenClaw):
```bash
openclaw tool protocol-m.identity_init
```

Or run the bundled CLI directly (useful for local debugging):
```bash
protocol-m identity init
protocol-m identity show
```

### Moltbook bind (happy path)
1) In Moltbook UI: Settings → Verify Identity → Get Challenge
2) Sign it:
```bash
protocol-m sign-message "<challenge>"
```
3) Paste signature into Moltbook "Bind".

### Create a verified post
- Save your post body to `post.txt` exactly as it will be published.
- Sign:
```bash
protocol-m sign post.txt --output post.sig.json
```
- Attach/paste the envelope JSON to Moltbook post creation as `signatureEnvelope`.

---

## 9) Development Milestones (ship v1.0.0 to ClawHub)

Ordered, with correctness gates early:

### M0 — Scaffold + golden gate (day 1–2)
- Create repo/skill skeleton (files above)
- Add `fixtures/golden-vector.json` from **`02-Projects/protocol-m/golden-vector.json`**
- Implement `didKey.ts`, `sha256.ts`, `jcs.ts`, `ed25519.ts`
- Implement `tests/golden.test.ts` and make it pass **before** building CLI

**Exit criteria:** Golden vector passes on Linux/macOS/Windows CI.

### M1 — Envelope + verification library (day 3–5)
- Implement `ArtifactEnvelopeSchema` + create/verify functions
- Implement strict error mapping (hash mismatch vs sig invalid vs did decode)
- Add tamper tests + canonical snapshots

**Exit criteria:** `sign/verify` logic correct; stable error reasons.

### M2 — Identity + encrypted keystore (day 6–10)
- Implement identity paths + permissions checks
- Implement age passphrase encryption storage (`root.key.enc` or versioned `keys/<did>.key.enc`)
- Implement identity state file `identity.json` and loadActiveSigner()
- Tests: wrong passphrase, rotation-safe writes (no corruption), unix perms gating

**Exit criteria:** "no plaintext secret on disk" + perms enforced.

### M3 — CLI + OpenClaw tool manifest (day 11–14)
- Implement `src/cli/*` commands with exit codes from **`02-Projects/protocol-m/PRD-phase-1.md`** §6
- Implement `skill.json` mapping tool names → `bin/protocol-m.mjs ...`
- Add JSON output modes for automation

**Exit criteria:** All PRD commands functional; exit codes stable.

### M4 — Rotation certificates (day 15–18)
- Implement `rotation.ts` create/verify per **`PRD-phase-1.md`** §7
- Wire to `identity rotate`
- Add tests: tamper, did mismatch, sig invalid

**Exit criteria:** Rotation certs verify and are produced on rotate.

### M5 — Moltbook workflow helpers + prompts (day 19–22)
- Add prompts: `prompts/moltbook-bind.md` guiding operator through challenge→sign→bind
- Optional: implement `moltbook challenge/bind` tools if API access is available
- Add `moltbook sign-post` convenience wrapper to avoid "byte drift"

**Exit criteria:** 5-minute proof workflow documented and smooth (matches **`PRD-phase-1.md`** §0).

### M6 — Release hardening + publish v1.0.0 (day 23–28)
- Add CI matrix (linux/mac/windows), run tests + lint
- Add `scripts/prepublish-check.mjs` to fail if golden or fixtures missing
- Write `CHANGELOG.md`
- Publish to ClawHub as `protocol-m@1.0.0`

**Exit criteria:** Installable from ClawHub; reproducible outputs; golden gate enforced.

---

## Notes

If you share (or point me to) the exact OpenClaw "skill tool manifest" schema (the real equivalent of the `skill.json` I proposed), I can tailor the tool registration fields (names, args schema, stdin/stdout behavior) to match OpenClaw's runtime precisely.

---

**Cost:** $1.52 | **Time:** 3m27s | **Model:** gpt-5.2-pro
