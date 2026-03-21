import { describe, expect, it } from 'vitest';

import { parseTaskSpecV1 } from '../src/task-spec.js';

const validTaskSpec = {
  version: '1',
  objective: 'Implement structured task spec validation',
  repo: 'clawbureau/clawverify-cli',
  base_ref: 'main',
  files_hint: ['src/work-submit.ts'],
  validation: {
    commands: ['pnpm typecheck'],
    timeout_seconds: 300,
  },
  constraints: {
    max_files_changed: 20,
    forbidden_patterns: ['rm -rf'],
    required_proof_tier: 'gateway',
    assurance_requirements: {
      version: '1',
      required_assurance_level: 'gateway',
      required_privacy_posture: 'caution',
      required_processors: ['openai', 'anthropic'],
      approval_policy: 'human_approval_receipt',
    },
  },
  deliverables: ['proof_bundle', 'did_signature'],
} as const;

describe('parseTaskSpecV1', () => {
  it('accepts a valid task spec payload', () => {
    const result = parseTaskSpecV1(validTaskSpec);

    expect(result.ok).toBe(true);
    if (!result.ok) {
      throw new Error(`Expected valid task spec, got issues: ${JSON.stringify(result.issues)}`);
    }

    expect(result.taskSpec).toEqual(validTaskSpec);
  });

  it('rejects values that exceed schema bounds', () => {
    const result = parseTaskSpecV1({
      ...validTaskSpec,
      objective: 'x'.repeat(20_001),
      base_ref: 'b'.repeat(257),
      files_hint: ['f'.repeat(1_025)],
      validation: {
        commands: ['c'.repeat(513)],
        timeout_seconds: 86_401,
      },
      constraints: {
        max_files_changed: 100_001,
        forbidden_patterns: ['p'.repeat(257)],
        required_proof_tier: 'gateway',
      },
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      throw new Error('Expected invalid task spec');
    }

    expect(result.issues).toEqual(expect.arrayContaining([
      { path: 'task_spec.objective', message: 'must be at most 20000 characters' },
      { path: 'task_spec.base_ref', message: 'must be at most 256 characters' },
      { path: 'task_spec.files_hint[0]', message: 'must be at most 1024 characters' },
      { path: 'task_spec.validation.commands[0]', message: 'must be at most 512 characters' },
      {
        path: 'task_spec.validation.timeout_seconds',
        message: 'must be less than or equal to 86400',
      },
      {
        path: 'task_spec.constraints.max_files_changed',
        message: 'must be less than or equal to 100000',
      },
      {
        path: 'task_spec.constraints.forbidden_patterns[0]',
        message: 'must be at most 256 characters',
      },
    ]));
  });

  it('rejects unsupported assurance requirement sets', () => {
    const result = parseTaskSpecV1({
      ...validTaskSpec,
      constraints: {
        ...validTaskSpec.constraints,
        assurance_requirements: {
          version: '1',
          required_processors: ['OpenAI'],
          unsupported: true,
        },
      },
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      throw new Error('Expected invalid task spec');
    }

    expect(result.issues).toEqual(expect.arrayContaining([
      {
        path: 'task_spec.constraints.assurance_requirements',
        message: 'unexpected property: unsupported',
      },
      {
        path: 'task_spec.constraints.assurance_requirements.required_processors[0]',
        message: 'must match ^[a-z0-9][a-z0-9._:-]{0,119}$',
      },
    ]));
  });
});
