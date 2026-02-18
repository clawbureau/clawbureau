#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');

const ROADMAP_README_PATH = 'docs/roadmaps/clawsig-protocol-v0.2/README.md';
const ROADMAP_PRD_PATH = 'docs/roadmaps/clawsig-protocol-v0.2/prd.json';
const ROADMAP_PROGRESS_PATH = 'docs/roadmaps/clawsig-protocol-v0.2/progress.txt';

const MIN_TRACKED_CAV_LANE = 16;

function readText(relPath) {
  return fs.readFileSync(path.resolve(ROOT, relPath), 'utf8');
}

function readJson(relPath) {
  return JSON.parse(readText(relPath));
}

function parseMergedCavLanesFromGit() {
  const log = spawnSync(
    'git',
    ['log', '--merges', '--pretty=%H\t%s'],
    { cwd: ROOT, encoding: 'utf8' }
  );

  if ((log.status ?? 1) !== 0) {
    throw new Error(`git log failed: ${log.stderr || 'unknown error'}`);
  }

  const rows = String(log.stdout)
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);

  const lanes = new Map();

  for (const row of rows) {
    const [commit, subject = ''] = row.split('\t');
    const match = subject.match(
      /Merge pull request #(\d+) from [^\s]+\/(CAV-US-(\d+)[^\s]*)/i
    );
    if (!match) continue;

    const pr = Number(match[1]);
    const laneId = `CAV-US-${String(Number(match[3])).padStart(3, '0')}`;
    const laneNum = Number(match[3]);

    if (!Number.isFinite(laneNum) || laneNum < MIN_TRACKED_CAV_LANE) {
      continue;
    }

    if (!lanes.has(laneId)) {
      lanes.set(laneId, {
        id: laneId,
        lane_num: laneNum,
        pr,
        merge_commit: commit,
        merge_commit_short: commit.slice(0, 8),
      });
    }
  }

  return [...lanes.values()].sort((a, b) => a.lane_num - b.lane_num);
}

function extractPrdStoryMap(prd) {
  const stories = Array.isArray(prd?.userStories) ? prd.userStories : [];
  const byId = new Map();

  for (const story of stories) {
    if (!story || typeof story !== 'object') continue;
    if (typeof story.id !== 'string') continue;
    byId.set(story.id, story);
  }

  return byId;
}

function extractReferenceSet(prd) {
  const refs = Array.isArray(prd?.metadata?.references) ? prd.metadata.references : [];
  return new Set(
    refs
      .filter((r) => r && typeof r === 'object')
      .map((r) => `${String(r.pr ?? '')}|${String(r.merge_commit ?? '')}`)
  );
}

function lineContains(text, laneId, pr) {
  const safeLane = laneId.replace('-', '\\-');
  const regex = new RegExp(`${safeLane}[\\s\\S]{0,80}PR #${pr}`);
  return regex.test(text);
}

function validateSync() {
  const mergedLanes = parseMergedCavLanesFromGit();
  const readme = readText(ROADMAP_README_PATH);
  const progress = readText(ROADMAP_PROGRESS_PATH);
  const prd = readJson(ROADMAP_PRD_PATH);

  const storyMap = extractPrdStoryMap(prd);
  const referenceSet = extractReferenceSet(prd);

  const failures = [];

  for (const lane of mergedLanes) {
    const story = storyMap.get(lane.id);
    if (!story) {
      failures.push({
        lane: lane.id,
        check: 'prd.story_present',
        detail: `Missing userStories entry for ${lane.id}`,
      });
      continue;
    }

    if (story.passes !== true) {
      failures.push({
        lane: lane.id,
        check: 'prd.story_passes_true',
        detail: `${lane.id} must have passes=true in prd.json`,
      });
    }

    const notes = typeof story.notes === 'string' ? story.notes : '';
    if (!notes.includes(`PR #${lane.pr}`) || !notes.includes(lane.merge_commit)) {
      failures.push({
        lane: lane.id,
        check: 'prd.story_notes_evidence',
        detail: `${lane.id} notes must include PR #${lane.pr} and merge ${lane.merge_commit}`,
      });
    }

    if (!referenceSet.has(`#${lane.pr}|${lane.merge_commit}`)) {
      failures.push({
        lane: lane.id,
        check: 'prd.metadata_reference',
        detail: `metadata.references missing { pr: "#${lane.pr}", merge_commit: "${lane.merge_commit}" }`,
      });
    }

    if (!lineContains(readme, lane.id, lane.pr)) {
      failures.push({
        lane: lane.id,
        check: 'readme_lane_evidence',
        detail: `README.md missing ${lane.id} with PR #${lane.pr}`,
      });
    }

    if (!lineContains(progress, lane.id, lane.pr)) {
      failures.push({
        lane: lane.id,
        check: 'progress_lane_evidence',
        detail: `progress.txt missing ${lane.id} with PR #${lane.pr}`,
      });
    }
  }

  return {
    ok: failures.length === 0,
    min_tracked_lane: MIN_TRACKED_CAV_LANE,
    merged_lanes_checked: mergedLanes,
    checked_count: mergedLanes.length,
    failures,
  };
}

function run() {
  let summary;
  try {
    summary = validateSync();
  } catch (error) {
    summary = {
      ok: false,
      min_tracked_lane: MIN_TRACKED_CAV_LANE,
      merged_lanes_checked: [],
      checked_count: 0,
      failures: [
        {
          lane: 'n/a',
          check: 'internal_error',
          detail: error instanceof Error ? error.message : String(error),
        },
      ],
    };
  }

  if (!summary.ok) {
    console.error('[cav-roadmap-sync] FAIL');
    console.error(JSON.stringify(summary, null, 2));
    process.exit(1);
  }

  console.log('[cav-roadmap-sync] PASS');
  console.log(JSON.stringify(summary, null, 2));
}

run();
