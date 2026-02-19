import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

function sha256hex(input) {
  return createHash('sha256').update(input).digest('hex');
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function normalizeStringArray(values) {
  if (!Array.isArray(values)) return [];
  const out = [];
  const seen = new Set();
  for (const raw of values) {
    if (typeof raw !== 'string') continue;
    const value = raw.trim();
    if (!value || seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }
  return out;
}

function normalizeObjectiveProfile(profile) {
  const obj = asObject(profile);
  if (!obj) return null;

  const name = typeof obj.name === 'string' ? obj.name.trim() : '';
  const weightsObj = asObject(obj.weights);
  const tieBreakers = normalizeStringArray(obj.tie_breakers);

  if (!name || !weightsObj) return null;

  const quality = Number(weightsObj.quality);
  const speed = Number(weightsObj.speed);
  const cost = Number(weightsObj.cost);
  const safety = Number(weightsObj.safety);

  if (![quality, speed, cost, safety].every((value) => Number.isFinite(value) && value >= 0)) {
    return null;
  }

  const total = quality + speed + cost + safety;
  if (total <= 0) return null;

  return {
    name,
    weights: {
      quality: Number((quality / total).toFixed(4)),
      speed: Number((speed / total).toFixed(4)),
      cost: Number((cost / total).toFixed(4)),
      safety: Number((safety / total).toFixed(4)),
    },
    tie_breakers: tieBreakers,
  };
}

function parseRegistry(raw) {
  const root = asObject(raw);
  if (!root) throw new Error('registry must be a JSON object');

  const registryVersion = typeof root.registry_version === 'string' && root.registry_version.trim()
    ? root.registry_version.trim()
    : null;
  if (!registryVersion) throw new Error('registry_version is required');

  const contendersRaw = Array.isArray(root.contenders) ? root.contenders : [];
  const contenders = [];

  for (const row of contendersRaw) {
    const item = asObject(row);
    if (!item) continue;

    const contenderId = typeof item.contender_id === 'string' ? item.contender_id.trim() : '';
    const versionPin = typeof item.version_pin === 'string' ? item.version_pin.trim() : '';

    if (!contenderId || !versionPin) {
      throw new Error('registry contenders require contender_id + version_pin');
    }

    contenders.push({
      contender_id: contenderId,
      version_pin: versionPin,
      label: typeof item.label === 'string' ? item.label.trim() : null,
      model: typeof item.model === 'string' ? item.model.trim() : null,
      harness: typeof item.harness === 'string' ? item.harness.trim() : null,
      tools: normalizeStringArray(item.tools),
      skills: normalizeStringArray(item.skills),
      plugins: normalizeStringArray(item.plugins),
      prompt_template: typeof item.prompt_template === 'string' ? item.prompt_template.trim() : null,
    });
  }

  const objectiveProfilesRaw = Array.isArray(root.objective_profiles) ? root.objective_profiles : [];
  const objectiveProfiles = objectiveProfilesRaw
    .map((profile) => normalizeObjectiveProfile(profile))
    .filter(Boolean);

  const experimentsRaw = Array.isArray(root.experiments) ? root.experiments : [];
  const experiments = [];

  for (const row of experimentsRaw) {
    const item = asObject(row);
    if (!item) continue;

    const experimentId = typeof item.experiment_id === 'string' ? item.experiment_id.trim() : '';
    if (!experimentId) continue;

    const taskFingerprint = typeof item.task_fingerprint === 'string' ? item.task_fingerprint.trim() : null;
    const objectiveProfileName = typeof item.objective_profile_name === 'string' ? item.objective_profile_name.trim() : null;

    const armsRaw = Array.isArray(item.arms) ? item.arms : [];
    const arms = armsRaw
      .map((armRaw) => {
        const armObj = asObject(armRaw);
        if (!armObj) return null;

        const armId = typeof armObj.arm_id === 'string' ? armObj.arm_id.trim() : '';
        const contenderIds = normalizeStringArray(armObj.contender_ids);
        if (!armId || contenderIds.length === 0) return null;

        return { arm_id: armId, contender_ids: contenderIds };
      })
      .filter(Boolean);

    if (arms.length === 0) continue;

    const allocationObj = asObject(item.allocation) ?? {};
    const allocation = {};
    for (const arm of arms) {
      const weight = Number(allocationObj[arm.arm_id]);
      if (Number.isFinite(weight) && weight > 0) {
        allocation[arm.arm_id] = weight;
      }
    }

    experiments.push({
      experiment_id: experimentId,
      task_fingerprint: taskFingerprint,
      objective_profile_name: objectiveProfileName,
      arms,
      allocation,
    });
  }

  return {
    registry_version: registryVersion,
    contenders,
    objective_profiles: objectiveProfiles,
    experiments,
  };
}

function chooseArm(experiment, seed, explicitArm) {
  const normalizedExplicit = typeof explicitArm === 'string' ? explicitArm.trim() : '';
  if (normalizedExplicit) {
    const match = experiment.arms.find((arm) => arm.arm_id === normalizedExplicit);
    if (!match) {
      throw new Error(`experiment arm '${normalizedExplicit}' not found for experiment '${experiment.experiment_id}'`);
    }
    return match;
  }

  const weights = experiment.arms.map((arm) => {
    const configured = Number(experiment.allocation?.[arm.arm_id]);
    const weight = Number.isFinite(configured) && configured > 0 ? configured : 1;
    return { ...arm, weight };
  });

  const totalWeight = weights.reduce((sum, arm) => sum + arm.weight, 0);
  if (totalWeight <= 0) return weights[0];

  const rollSource = sha256hex(`${experiment.experiment_id}:${seed}`);
  const rollInt = Number.parseInt(rollSource.slice(0, 8), 16);
  const roll = rollInt / 0xffffffff;

  let cursor = 0;
  for (const arm of weights) {
    cursor += arm.weight / totalWeight;
    if (roll <= cursor) return arm;
  }

  return weights[weights.length - 1];
}

export function loadContenderRegistry(filePath) {
  const raw = JSON.parse(readFileSync(filePath, 'utf8'));
  return parseRegistry(raw);
}

export function resolveRegistryArenaInput({
  registry,
  baseContenders,
  taskFingerprint,
  objectiveProfileName,
  experimentId,
  experimentArm,
  arenaSeed,
}) {
  const registryById = new Map(registry.contenders.map((row) => [row.contender_id, row]));

  const mergedContenders = baseContenders.map((contender) => {
    const contenderId = String(contender?.contender_id ?? '').trim();
    if (!contenderId) {
      throw new Error('contenders entries must include contender_id');
    }

    const reg = registryById.get(contenderId);
    if (!reg) {
      return {
        ...contender,
        version_pin: null,
        prompt_template: null,
        experiment_arm: null,
      };
    }

    return {
      ...contender,
      label: reg.label ?? contender.label,
      model: reg.model ?? contender.model,
      harness: reg.harness ?? contender.harness,
      tools: reg.tools.length > 0 ? reg.tools : contender.tools,
      skills: reg.skills.length > 0 ? reg.skills : contender.skills,
      plugins: reg.plugins.length > 0 ? reg.plugins : contender.plugins,
      version_pin: reg.version_pin,
      prompt_template: reg.prompt_template,
      experiment_arm: null,
    };
  });

  let selectedExperiment = null;

  if (experimentId) {
    selectedExperiment = registry.experiments.find((row) => row.experiment_id === experimentId) ?? null;
    if (!selectedExperiment) {
      throw new Error(`experiment '${experimentId}' not found in contender registry`);
    }
  } else if (taskFingerprint) {
    selectedExperiment = registry.experiments.find((row) => row.task_fingerprint === taskFingerprint) ?? null;
  }

  let selectedArm = null;
  let selectedContenders = mergedContenders;

  if (selectedExperiment) {
    selectedArm = chooseArm(selectedExperiment, arenaSeed ?? taskFingerprint ?? 'arena-seed', experimentArm);
    const allowed = new Set(selectedArm.contender_ids);
    selectedContenders = mergedContenders
      .filter((row) => allowed.has(String(row.contender_id)))
      .map((row) => ({ ...row, experiment_arm: selectedArm.arm_id }));

    if (selectedContenders.length === 0) {
      throw new Error(`experiment '${selectedExperiment.experiment_id}' arm '${selectedArm.arm_id}' produced zero contenders`);
    }
  }

  const resolvedObjectiveName = objectiveProfileName
    ?? selectedExperiment?.objective_profile_name
    ?? null;

  const resolvedObjectiveProfile = resolvedObjectiveName
    ? (registry.objective_profiles.find((profile) => profile.name === resolvedObjectiveName) ?? null)
    : null;

  if (resolvedObjectiveName && !resolvedObjectiveProfile) {
    throw new Error(`objective profile '${resolvedObjectiveName}' not found in contender registry`);
  }

  return {
    contenders: selectedContenders,
    objective_profile: resolvedObjectiveProfile,
    registry_context: {
      registry_version: registry.registry_version,
      experiment_id: selectedExperiment?.experiment_id ?? null,
      experiment_arm: selectedArm?.arm_id ?? null,
      objective_profile_name: resolvedObjectiveName,
      selected_contenders: selectedContenders.map((row) => ({
        contender_id: row.contender_id,
        version_pin: row.version_pin ?? null,
      })),
    },
  };
}
