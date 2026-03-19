import { describe, expect, it } from 'vitest';
import { applyVisibility } from '../../../packages/clawverify-cli/src/epv-crypto.js';
import {
  didFromPublicKey,
  exportKeyPairJWK,
  generateKeyPair,
} from '../../../packages/clawsig-sdk/src/crypto.js';
import {
  decryptBundleForIdentity,
  extractPublicLayer,
  type InspectDecryptError,
} from '../src/inspect-crypto.js';
import type { ViewerIdentity } from '../src/inspect-identity.js';

async function createViewerIdentity(): Promise<ViewerIdentity> {
  const keyPair = await generateKeyPair();
  const did = await didFromPublicKey(keyPair.publicKey);
  const jwk = await exportKeyPairJWK(keyPair);

  return {
    did,
    publicKeyJwk: jwk.publicKey,
    privateKeyJwk: jwk.privateKey,
  };
}

describe('inspect crypto decryption', () => {
  it('decrypts payload encrypted via EPV-002 applyVisibility', async () => {
    const identity = await createViewerIdentity();

    const payload: Record<string, unknown> = {
      bundle_id: 'bundle_epv005_001',
      agent_did: identity.did,
      event_chain: [{ event_hash: 'abc' }],
      tool_receipts: [{ tool_name: 'ripgrep' }, { tool_name: 'bash' }],
      execution_receipts: [{ command: 'rg --files' }],
      side_effect_receipts: [{ path: '/workspace/proof_bundle.v2.json' }],
      network_receipts: [{ host: 'api.github.com' }],
    };

    applyVisibility(payload, 'owner', [identity.did], identity.did);

    const bundle: Record<string, unknown> = {
      signer_did: identity.did,
      issued_at: '2026-03-19T00:00:00.000Z',
      payload,
    };

    const publicLayer = extractPublicLayer(bundle);
    expect(publicLayer.bundle_version).toBe('2');
    expect(publicLayer.has_encrypted_payload).toBe(true);
    expect(publicLayer.viewer_dids).toContain(identity.did);

    const decrypted = await decryptBundleForIdentity(bundle, identity);
    expect(Array.isArray(decrypted.tool_receipts)).toBe(true);
    expect(Array.isArray(decrypted.execution_receipts)).toBe(true);
    expect(Array.isArray(decrypted.side_effect_receipts)).toBe(true);
    expect(Array.isArray(decrypted.network_receipts)).toBe(true);
  });

  it('fails closed for an identity not listed in viewer_keys', async () => {
    const ownerIdentity = await createViewerIdentity();
    const outsiderIdentity = await createViewerIdentity();

    const payload: Record<string, unknown> = {
      bundle_id: 'bundle_epv005_002',
      agent_did: ownerIdentity.did,
      tool_receipts: [{ tool_name: 'curl' }],
    };

    applyVisibility(payload, 'owner', [ownerIdentity.did], ownerIdentity.did);

    const bundle: Record<string, unknown> = {
      signer_did: ownerIdentity.did,
      issued_at: '2026-03-19T00:00:00.000Z',
      payload,
    };

    await expect(decryptBundleForIdentity(bundle, outsiderIdentity)).rejects.toMatchObject({
      name: 'InspectDecryptError',
      code: 'INSPECT_NOT_AUTHORIZED',
    } satisfies Partial<InspectDecryptError>);
  });
});
