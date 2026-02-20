function clamp(value, min = 0, max = 100) {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, value));
}

function avg(values) {
  if (!Array.isArray(values) || values.length === 0) return 0;
  const nums = values.filter((v) => Number.isFinite(v));
  if (nums.length === 0) return 0;
  return nums.reduce((sum, item) => sum + item, 0) / nums.length;
}

export function computeMaintainabilityScore(signals) {
  const sourceBytes = Number(signals?.source_bytes ?? 0);
  const scriptLines = Number(signals?.inline_script_lines ?? 0);
  const styleBlocks = Number(signals?.inline_style_blocks ?? 0);
  const domNodes = Number(signals?.dom_node_count ?? 0);
  const evalCount = Number(signals?.eval_occurrences ?? 0);

  let score = 100;

  if (sourceBytes > 120_000) score -= 20;
  else if (sourceBytes > 80_000) score -= 12;
  else if (sourceBytes > 60_000) score -= 7;

  if (scriptLines > 420) score -= 20;
  else if (scriptLines > 320) score -= 12;
  else if (scriptLines > 220) score -= 6;

  if (styleBlocks > 4) score -= 12;
  else if (styleBlocks > 2) score -= 6;

  if (domNodes > 900) score -= 10;
  else if (domNodes > 650) score -= 6;

  if (evalCount > 0) score -= 20;

  return clamp(score);
}

export function computeUiDuelScores(input) {
  const journey = input?.journey ?? {};
  const lighthouse = input?.lighthouse ?? {};
  const maintainabilitySignals = input?.maintainability ?? {};
  const weights = input?.weights ?? {
    ux_task_success_friction: 35,
    visual_quality_consistency: 20,
    performance: 20,
    accessibility: 15,
    implementation_maintainability: 10,
  };

  const flowStates = [
    Boolean(journey?.flows?.browse),
    Boolean(journey?.flows?.details),
    Boolean(journey?.flows?.claim),
    Boolean(journey?.flows?.submit),
  ];

  const flowSuccessCount = flowStates.filter(Boolean).length;
  const flowSuccessRate = flowSuccessCount / flowStates.length;

  const timingValues = [
    Number(journey?.timings_ms?.browse ?? 0),
    Number(journey?.timings_ms?.details ?? 0),
    Number(journey?.timings_ms?.claim ?? 0),
    Number(journey?.timings_ms?.submit ?? 0),
  ].filter((value) => Number.isFinite(value) && value > 0);

  const avgTimingMs = avg(timingValues);
  const frictionEvents = Number(journey?.friction_events ?? 0);

  const consoleErrors = Number(journey?.console?.error_count ?? 0);
  const runtimeErrors = Number(journey?.runtime_errors?.length ?? 0);
  const criticalAccessibilityViolations = Number(journey?.accessibility?.critical_violations ?? 0);

  const performanceScore = clamp(Number(lighthouse?.categories?.performance_score ?? 0) * 100);
  const lighthouseAccessibilityScore = clamp(Number(lighthouse?.categories?.accessibility_score ?? 0) * 100);
  const clsValue = Number(lighthouse?.metrics?.cls ?? 0);
  const warnCount = Number(journey?.console?.warn_count ?? 0);

  const uxBase = flowSuccessRate * 100;
  const timingPenalty = avgTimingMs > 0 ? Math.min(30, Math.max(0, (avgTimingMs - 1200) / 220)) : 0;
  const frictionPenalty = Math.min(35, frictionEvents * 6);
  const uxScore = clamp(uxBase - timingPenalty - frictionPenalty);

  const visualPenalty = Math.min(55, Math.max(0, clsValue * 1000) + (warnCount * 1.5) + (consoleErrors * 8));
  const visualScore = clamp(100 - visualPenalty);

  const accessibilityPenalty = Math.min(80, criticalAccessibilityViolations * 30);
  const accessibilityScore = clamp((lighthouseAccessibilityScore * 0.7) + ((100 - accessibilityPenalty) * 0.3));

  const implementationMaintainability = computeMaintainabilityScore(maintainabilitySignals);

  const weighted = {
    ux_task_success_friction: uxScore,
    visual_quality_consistency: visualScore,
    performance: performanceScore,
    accessibility: accessibilityScore,
    implementation_maintainability: implementationMaintainability,
  };

  const weightedTotal =
    ((weighted.ux_task_success_friction * Number(weights.ux_task_success_friction ?? 0)) +
      (weighted.visual_quality_consistency * Number(weights.visual_quality_consistency ?? 0)) +
      (weighted.performance * Number(weights.performance ?? 0)) +
      (weighted.accessibility * Number(weights.accessibility ?? 0)) +
      (weighted.implementation_maintainability * Number(weights.implementation_maintainability ?? 0))) / 100;

  const hardGates = {
    core_flows_pass: flowSuccessCount === flowStates.length,
    no_critical_runtime_errors: consoleErrors === 0 && runtimeErrors === 0,
    no_critical_accessibility_violations: criticalAccessibilityViolations === 0,
  };

  const hardGatePassed = hardGates.core_flows_pass
    && hardGates.no_critical_runtime_errors
    && hardGates.no_critical_accessibility_violations;

  const reasonCodes = [];
  if (!hardGates.core_flows_pass) reasonCodes.push('ARENA_UI_DUEL_GATE_CORE_FLOWS_FAIL');
  if (!hardGates.no_critical_runtime_errors) reasonCodes.push('ARENA_UI_DUEL_GATE_RUNTIME_ERRORS');
  if (!hardGates.no_critical_accessibility_violations) reasonCodes.push('ARENA_UI_DUEL_GATE_A11Y_CRITICAL');

  return {
    hard_gates: hardGates,
    hard_gate_passed: hardGatePassed,
    weighted_scores: weighted,
    weighted_total: Number(weightedTotal.toFixed(2)),
    final_score: hardGatePassed ? Number(weightedTotal.toFixed(2)) : 0,
    diagnostics: {
      flow_success_count: flowSuccessCount,
      flow_total: flowStates.length,
      flow_success_rate: Number(flowSuccessRate.toFixed(4)),
      avg_timing_ms: Number(avgTimingMs.toFixed(2)),
      friction_events: frictionEvents,
      console_error_count: consoleErrors,
      runtime_error_count: runtimeErrors,
      critical_accessibility_violations: criticalAccessibilityViolations,
      cls: Number((Number.isFinite(clsValue) ? clsValue : 0).toFixed(4)),
    },
    reason_codes: reasonCodes,
  };
}
