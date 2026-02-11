import * as fs from "fs";
import * as path from "path";
import * as os from "os";

export interface UsageState {
  updatedAt: string;
  brave: {
    freeWebSearch: number;
    proWebSearch: number;
    groundingRequests: number;
  };
  exa: {
    searchCalls: number;
    contextCalls: number;
    answerCalls: number;
    contentsPieces: number;
  };
}

const DEFAULT_USAGE_PATH = path.join(
  os.homedir(),
  ".clawbureau-secrets",
  "clawea-www-usage.json",
);

function usagePath(): string {
  return process.env.CLAWEA_USAGE_FILE || DEFAULT_USAGE_PATH;
}

function parseNum(v: string | undefined): number | undefined {
  if (!v) return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

export const EXA_PRICING = {
  // Based on Exa pricing screenshots provided by user (Pay as you go).
  // Search: $5 / 1k neural/auto searches (1-25 results)
  searchCallUsd: 5 / 1000,
  // Content: $1 / 1k pieces of content
  contentPieceUsd: 1 / 1000,
  // Answer: $5 / 1k answers
  answerUsd: 5 / 1000,
  // /context isn't explicitly listed; treat as a search call for budgeting.
  contextCallUsd: 5 / 1000,
} as const;

export function estimateExaSpendUsd(state: UsageState): number {
  return (
    state.exa.searchCalls * EXA_PRICING.searchCallUsd +
    state.exa.contextCalls * EXA_PRICING.contextCallUsd +
    state.exa.answerCalls * EXA_PRICING.answerUsd +
    state.exa.contentsPieces * EXA_PRICING.contentPieceUsd
  );
}

export function loadUsageState(): UsageState {
  const fp = usagePath();
  if (!fs.existsSync(fp)) {
    return {
      updatedAt: new Date().toISOString(),
      brave: { freeWebSearch: 0, proWebSearch: 0, groundingRequests: 0 },
      exa: { searchCalls: 0, contextCalls: 0, answerCalls: 0, contentsPieces: 0 },
    };
  }
  const raw = fs.readFileSync(fp, "utf-8");
  const data = JSON.parse(raw) as UsageState;
  return {
    updatedAt: data.updatedAt ?? new Date().toISOString(),
    brave: {
      freeWebSearch: data.brave?.freeWebSearch ?? 0,
      proWebSearch: data.brave?.proWebSearch ?? 0,
      groundingRequests: data.brave?.groundingRequests ?? 0,
    },
    exa: {
      searchCalls: data.exa?.searchCalls ?? 0,
      contextCalls: data.exa?.contextCalls ?? 0,
      answerCalls: data.exa?.answerCalls ?? 0,
      contentsPieces: data.exa?.contentsPieces ?? 0,
    },
  };
}

export function saveUsageState(state: UsageState): void {
  const fp = usagePath();
  fs.mkdirSync(path.dirname(fp), { recursive: true });
  fs.writeFileSync(fp, JSON.stringify({ ...state, updatedAt: new Date().toISOString() }, null, 2));
}

export function getBudgets(): {
  braveFreeMax: number | null;
  braveProMax: number | null;
  braveGroundingMax: number | null;
  exaBudgetUsd: number | null;
} {
  return {
    braveFreeMax: parseNum(process.env.BRAVE_FREE_MAX_REQUESTS) ?? null,
    braveProMax: parseNum(process.env.BRAVE_PRO_MAX_REQUESTS) ?? null,
    braveGroundingMax: parseNum(process.env.BRAVE_GROUNDING_MAX_REQUESTS) ?? null,
    exaBudgetUsd: parseNum(process.env.EXA_BUDGET_DOLLARS) ?? null,
  };
}

export function assertCanConsume(state: UsageState, delta: Partial<UsageState["brave"]> & Partial<UsageState["exa"]>): void {
  const budgets = getBudgets();

  const next: UsageState = JSON.parse(JSON.stringify(state));
  if (delta.freeWebSearch) next.brave.freeWebSearch += delta.freeWebSearch;
  if (delta.proWebSearch) next.brave.proWebSearch += delta.proWebSearch;
  if (delta.groundingRequests) next.brave.groundingRequests += delta.groundingRequests;

  if ((delta as any).searchCalls) next.exa.searchCalls += (delta as any).searchCalls;
  if ((delta as any).contextCalls) next.exa.contextCalls += (delta as any).contextCalls;
  if ((delta as any).answerCalls) next.exa.answerCalls += (delta as any).answerCalls;
  if ((delta as any).contentsPieces) next.exa.contentsPieces += (delta as any).contentsPieces;

  if (budgets.braveFreeMax !== null && next.brave.freeWebSearch > budgets.braveFreeMax) {
    throw new Error(
      `Budget exceeded: BRAVE_FREE_MAX_REQUESTS=${budgets.braveFreeMax} (would be ${next.brave.freeWebSearch})`,
    );
  }
  if (budgets.braveProMax !== null && next.brave.proWebSearch > budgets.braveProMax) {
    throw new Error(
      `Budget exceeded: BRAVE_PRO_MAX_REQUESTS=${budgets.braveProMax} (would be ${next.brave.proWebSearch})`,
    );
  }
  if (budgets.braveGroundingMax !== null && next.brave.groundingRequests > budgets.braveGroundingMax) {
    throw new Error(
      `Budget exceeded: BRAVE_GROUNDING_MAX_REQUESTS=${budgets.braveGroundingMax} (would be ${next.brave.groundingRequests})`,
    );
  }

  if (budgets.exaBudgetUsd !== null) {
    const spend = estimateExaSpendUsd(next);
    if (spend > budgets.exaBudgetUsd) {
      throw new Error(
        `Budget exceeded: EXA_BUDGET_DOLLARS=$${budgets.exaBudgetUsd} (would be ~$${spend.toFixed(2)})`,
      );
    }
  }
}

export function consume(
  delta: Partial<UsageState["brave"]> & Partial<UsageState["exa"]>,
): UsageState {
  const state = loadUsageState();
  assertCanConsume(state, delta);

  const next = loadUsageState();
  if (delta.freeWebSearch) next.brave.freeWebSearch += delta.freeWebSearch;
  if (delta.proWebSearch) next.brave.proWebSearch += delta.proWebSearch;
  if (delta.groundingRequests) next.brave.groundingRequests += delta.groundingRequests;

  if ((delta as any).searchCalls) next.exa.searchCalls += (delta as any).searchCalls;
  if ((delta as any).contextCalls) next.exa.contextCalls += (delta as any).contextCalls;
  if ((delta as any).answerCalls) next.exa.answerCalls += (delta as any).answerCalls;
  if ((delta as any).contentsPieces) next.exa.contentsPieces += (delta as any).contentsPieces;

  saveUsageState(next);
  return next;
}

export function usageSummary(state: UsageState): string {
  const exaSpend = estimateExaSpendUsd(state);
  const budgets = getBudgets();
  return [
    `Brave free web: ${state.brave.freeWebSearch}${budgets.braveFreeMax ? `/${budgets.braveFreeMax}` : ""}`,
    `Brave pro web: ${state.brave.proWebSearch}${budgets.braveProMax ? `/${budgets.braveProMax}` : ""}`,
    `Brave grounding: ${state.brave.groundingRequests}${budgets.braveGroundingMax ? `/${budgets.braveGroundingMax}` : ""}`,
    `Exa search: ${state.exa.searchCalls}`, 
    `Exa context: ${state.exa.contextCalls}`, 
    `Exa contents pieces: ${state.exa.contentsPieces}`, 
    `Exa est spend: ~$${exaSpend.toFixed(2)}${budgets.exaBudgetUsd ? `/$${budgets.exaBudgetUsd}` : ""}`,
  ].join(" | ");
}
