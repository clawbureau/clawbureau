import type { ProofBundlePayload } from './types.js';

interface TraceEvent {
  timestamp: string;
  token: string;
}

function didPrefix(did: string): string {
  const parts = did.split(':');
  if (parts.length < 3) return did.slice(0, 20);
  const method = parts[1];
  const id = parts.slice(2).join(':');
  return `did:${method}:${id.slice(0, 6)}`;
}

/**
 * Compile a proof bundle into a deterministic semantic trace string.
 * Privacy-preserving: uses only structural metadata, never content.
 */
export function compileSemanticTrace(bundle: ProofBundlePayload): string {
  const events: TraceEvent[] = [];

  if (bundle.receipts) {
    for (const envelope of bundle.receipts) {
      const p = envelope.payload;
      events.push({ timestamp: p.timestamp, token: `[LLM:${p.provider}/${p.model}]` });
    }
  }

  if (bundle.tool_receipts) {
    for (const tr of bundle.tool_receipts) {
      events.push({ timestamp: tr.timestamp, token: `[TOOL:${tr.tool_name}]` });
    }
  }

  if (bundle.side_effect_receipts) {
    for (const ser of bundle.side_effect_receipts) {
      events.push({ timestamp: ser.timestamp, token: `[EFFECT:${ser.effect_class}]` });
    }
  }

  if (bundle.human_approval_receipts) {
    for (const har of bundle.human_approval_receipts) {
      events.push({ timestamp: har.timestamp, token: '[HUMAN_APPROVAL]' });
    }
  }

  if (bundle.delegation_receipts) {
    for (const dr of bundle.delegation_receipts) {
      events.push({ timestamp: dr.delegated_at, token: `[DELEGATE:${didPrefix(dr.delegate_did)}]` });
    }
  }

  events.sort((a, b) => a.timestamp.localeCompare(b.timestamp));

  const agentPrefix = `[AGENT:${didPrefix(bundle.agent_did)}]`;
  const tokens = events.map((e) => e.token).join(' ');

  return tokens.length > 0 ? `${agentPrefix} ${tokens}` : agentPrefix;
}
