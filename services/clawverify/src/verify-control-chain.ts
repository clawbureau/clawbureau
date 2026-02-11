import type {
  RemediationHint,
  VerificationError,
  VerifyControlChainRequest,
  VerifyControlChainResponse,
} from './types';
import { isValidDidFormat } from './schema-registry';

interface VerifyControlChainOptions {
  clawclaimBaseUrl?: string;
  timeoutMs?: number;
  fetcher?: typeof fetch;
}

interface ControlChainLookupRecord {
  status: 'ok';
  owner_did: string;
  chain: {
    owner_did: string;
    controller_did: string;
    agent_did: string;
    policy_hash_b64u: string;
    active: boolean;
  };
  controller: {
    controller_did: string;
    owner_did: string;
    active: boolean;
    policy?: {
      policy_hash_b64u?: string;
      owner_did?: string;
    };
  };
  agent_binding: {
    controller_did: string;
    agent_did: string;
    owner_did: string;
    active: boolean;
    policy_hash_b64u?: string;
  };
}

function hint(code: RemediationHint['code'], message: string, action: string): RemediationHint {
  return { code, message, action };
}

function invalid(
  now: string,
  req: { ownerDid: string; controllerDid: string; agentDid: string },
  reason: string,
  error: VerificationError,
  remediation_hints: RemediationHint[]
): VerifyControlChainResponse {
  return {
    result: {
      status: 'INVALID',
      reason,
      verified_at: now,
    },
    owner_did: req.ownerDid,
    controller_did: req.controllerDid,
    agent_did: req.agentDid,
    chain_active: false,
    remediation_hints,
    error,
  };
}

export async function verifyControlChain(
  body: unknown,
  options: VerifyControlChainOptions = {}
): Promise<VerifyControlChainResponse> {
  const now = new Date().toISOString();

  if (!body || typeof body !== 'object') {
    return invalid(
      now,
      { ownerDid: '', controllerDid: '', agentDid: '' },
      'Request must be an object',
      {
        code: 'PARSE_ERROR',
        message: 'Request body must be a JSON object',
      },
      [
        hint(
          'CHECK_CONTROL_CHAIN_CONFIG',
          'Provide owner_did, controller_did, and agent_did fields',
          'Ensure verify-control-chain request includes all required DID fields'
        ),
      ]
    );
  }

  const req = body as Partial<VerifyControlChainRequest>;
  const ownerDid = typeof req.owner_did === 'string' ? req.owner_did.trim() : '';
  const controllerDid = typeof req.controller_did === 'string' ? req.controller_did.trim() : '';
  const agentDid = typeof req.agent_did === 'string' ? req.agent_did.trim() : '';

  if (!ownerDid || !controllerDid || !agentDid) {
    return invalid(
      now,
      { ownerDid, controllerDid, agentDid },
      'owner_did, controller_did, and agent_did are required',
      {
        code: 'MISSING_REQUIRED_FIELD',
        message: 'owner_did, controller_did, and agent_did are required',
      },
      [
        hint(
          'CHECK_CONTROL_CHAIN_CONFIG',
          'Missing required DID values for control-chain verification',
          'Include owner_did, controller_did, and agent_did in the request'
        ),
      ]
    );
  }

  if (!isValidDidFormat(ownerDid) || !isValidDidFormat(controllerDid) || !isValidDidFormat(agentDid)) {
    return invalid(
      now,
      { ownerDid, controllerDid, agentDid },
      'One or more DID fields are malformed',
      {
        code: 'INVALID_DID_FORMAT',
        message: 'owner_did, controller_did, and agent_did must be valid DID strings',
      },
      [
        hint(
          'CHECK_CONTROL_CHAIN_CONFIG',
          'Control-chain verification requires canonical DID formatting',
          'Fix DID formatting before retrying'
        ),
      ]
    );
  }

  const baseUrl = options.clawclaimBaseUrl?.trim();
  if (!baseUrl) {
    return invalid(
      now,
      { ownerDid, controllerDid, agentDid },
      'clawclaim base URL is not configured',
      {
        code: 'DEPENDENCY_NOT_CONFIGURED',
        message: 'CLAWCLAIM_BASE_URL is required for control-chain verification',
      },
      [
        hint(
          'CHECK_CONTROL_CHAIN_CONFIG',
          'Control-chain dependency is not configured',
          'Set CLAWCLAIM_BASE_URL in clawverify environment'
        ),
      ]
    );
  }

  const timeoutMs = options.timeoutMs && Number.isFinite(options.timeoutMs) ? options.timeoutMs : 5000;
  const fetcher = options.fetcher ?? fetch;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  let responseJson: unknown = null;

  try {
    const target = `${baseUrl.replace(/\/$/, '')}/v1/control-plane/controllers/${encodeURIComponent(controllerDid)}/agents/${encodeURIComponent(agentDid)}`;
    response = await fetcher(target, {
      method: 'GET',
      headers: {
        accept: 'application/json',
      },
      signal: controller.signal,
    });

    const text = await response.text();
    try {
      responseJson = text ? (JSON.parse(text) as unknown) : null;
    } catch {
      responseJson = null;
    }
  } catch (err) {
    clearTimeout(timer);
    const errorMessage = err instanceof Error ? err.message : String(err);
    return invalid(
      now,
      { ownerDid, controllerDid, agentDid },
      'Failed to lookup control-chain from clawclaim',
      {
        code: 'DEPENDENCY_NOT_CONFIGURED',
        message: errorMessage.includes('aborted')
          ? 'Control-chain lookup timed out'
          : 'Control-chain lookup failed',
      },
      [
        hint(
          'CHECK_CONTROL_CHAIN_CONFIG',
          'Could not query clawclaim for control-chain state',
          'Verify clawclaim staging deployment and network reachability'
        ),
      ]
    );
  } finally {
    clearTimeout(timer);
  }

  if (response.status === 404) {
    return invalid(
      now,
      { ownerDid, controllerDid, agentDid },
      'Control-chain record was not found',
      {
        code: 'CONTROL_CHAIN_NOT_FOUND',
        message: 'No controller/agent chain exists for the requested pair',
      },
      [
        hint(
          'REGISTER_CONTROLLER',
          'Controller is not registered under the owner',
          'Register controller in clawclaim control-plane'
        ),
        hint(
          'REGISTER_AGENT_UNDER_CONTROLLER',
          'Agent is not registered under this controller',
          'Register agent under controller in clawclaim control-plane'
        ),
      ]
    );
  }

  if (response.status !== 200) {
    const upstreamError =
      responseJson && typeof responseJson === 'object'
        ? (responseJson as Record<string, unknown>).error
        : null;

    return invalid(
      now,
      { ownerDid, controllerDid, agentDid },
      'Control-chain lookup failed',
      {
        code: 'DEPENDENCY_NOT_CONFIGURED',
        message: `clawclaim lookup failed (${response.status})${
          typeof upstreamError === 'string' ? `: ${upstreamError}` : ''
        }`,
      },
      [
        hint(
          'CHECK_CONTROL_CHAIN_CONFIG',
          'clawclaim returned a non-success status for chain lookup',
          'Inspect clawclaim logs and verify route + env configuration'
        ),
      ]
    );
  }

  if (!responseJson || typeof responseJson !== 'object') {
    return invalid(
      now,
      { ownerDid, controllerDid, agentDid },
      'Control-chain response payload is malformed',
      {
        code: 'PARSE_ERROR',
        message: 'clawclaim response is not valid JSON object',
      },
      [
        hint(
          'CHECK_CONTROL_CHAIN_CONFIG',
          'Unexpected control-chain response shape from clawclaim',
          'Check clawclaim staging version and response contract'
        ),
      ]
    );
  }

  const record = responseJson as ControlChainLookupRecord;
  if (!record.chain || !record.controller || !record.agent_binding) {
    return invalid(
      now,
      { ownerDid, controllerDid, agentDid },
      'Control-chain response is missing required fields',
      {
        code: 'PARSE_ERROR',
        message: 'clawclaim response missing chain/controller/agent_binding fields',
      },
      [
        hint(
          'CHECK_CONTROL_CHAIN_CONFIG',
          'Control-chain response contract mismatch',
          'Align clawclaim and clawverify control-chain payload contracts'
        ),
      ]
    );
  }

  if (
    record.owner_did !== ownerDid ||
    record.chain.owner_did !== ownerDid ||
    record.chain.controller_did !== controllerDid ||
    record.chain.agent_did !== agentDid ||
    record.controller.owner_did !== ownerDid ||
    record.agent_binding.owner_did !== ownerDid
  ) {
    return invalid(
      now,
      { ownerDid, controllerDid, agentDid },
      'Control-chain context does not match requested owner/controller/agent',
      {
        code: 'CONTROL_CHAIN_CONTEXT_MISMATCH',
        message: 'Resolved control-chain does not match request context',
      },
      [
        hint(
          'REGISTER_CONTROLLER',
          'Controller owner binding does not match requested owner',
          'Re-register controller under the intended owner'
        ),
        hint(
          'REGISTER_AGENT_UNDER_CONTROLLER',
          'Agent binding owner/controller relation is inconsistent',
          'Re-register the agent under the correct controller'
        ),
      ]
    );
  }

  const chainActive =
    record.chain.active === true &&
    record.controller.active === true &&
    record.agent_binding.active === true;

  if (!chainActive) {
    return invalid(
      now,
      { ownerDid, controllerDid, agentDid },
      'Control-chain exists but is inactive',
      {
        code: 'CLAIM_NOT_FOUND',
        message: 'Controller or agent binding is inactive',
      },
      [
        hint(
          'REGISTER_CONTROLLER',
          'Controller binding is inactive',
          'Re-activate or re-register the controller binding'
        ),
        hint(
          'REGISTER_AGENT_UNDER_CONTROLLER',
          'Agent binding under controller is inactive',
          'Re-activate or re-register the agent binding'
        ),
      ]
    );
  }

  if (
    record.controller.policy?.owner_did &&
    record.controller.policy.owner_did !== ownerDid
  ) {
    return invalid(
      now,
      { ownerDid, controllerDid, agentDid },
      'Sensitive policy owner binding mismatch',
      {
        code: 'CONTROL_CHAIN_CONTEXT_MISMATCH',
        message: 'controller.policy.owner_did must match chain owner_did',
      },
      [
        hint(
          'UPDATE_SENSITIVE_POLICY',
          'Controller sensitive policy is not owner-bound to requested owner',
          'Update controller sensitive policy in clawclaim'
        ),
      ]
    );
  }

  return {
    result: {
      status: 'VALID',
      reason: 'Owner/controller/agent chain is valid and active',
      verified_at: now,
    },
    owner_did: ownerDid,
    controller_did: controllerDid,
    agent_did: agentDid,
    chain_active: true,
    policy_hash_b64u:
      record.chain.policy_hash_b64u ||
      record.controller.policy?.policy_hash_b64u ||
      record.agent_binding.policy_hash_b64u,
    remediation_hints: [],
  };
}
