import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const hex = /^[a-f0-9]{64}$/iu;
const own = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

export function policyDiff(verifiedSnapshot, trialPolicy) {
  const isObject = obj => obj !== null && typeof obj === 'object' && !Array.isArray(obj);
  const changes = [];
  function walk(before, after, path) {
    if (isObject(before) && isObject(after)) {
      for (const key of [...new Set([...Object.keys(before), ...Object.keys(after)])].sort()) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') throw new Error('unsafe_policy_key');
        const next = `${path}/${key.replace(/~/g, '~0').replace(/\//g, '~1')}`;
        if (!own(before, key)) changes.push({ path: next, change: 'remove_trial_only' });
        else if (!own(after, key)) changes.push({ path: next, change: 'restore_missing' });
        else walk(before[key], after[key], next);
      }
    } else if (JSON.stringify(before) !== JSON.stringify(after)) {
      changes.push({ path: path || '/', change: 'restore_value' });
    }
  }
  walk(verifiedSnapshot, trialPolicy, '');
  return changes;
}

export function previewPolicyRestore({ snapshotPath, trialPath, trustedSha256 }) {
  if (!snapshotPath || !trialPath || !hex.test(trustedSha256 ?? '')) throw new Error('trusted_snapshot_required');
  if (resolve(snapshotPath) === resolve(trialPath)) throw new Error('distinct_policy_paths_required');
  // The SHA-256 must be independently recorded before the incident.
  const snapshotBytes = readFileSync(snapshotPath);
  const actualDigest = createHash('sha256').update(snapshotBytes).digest('hex');
  if (actualDigest !== trustedSha256.toLowerCase()) throw new Error('snapshot_integrity_failed');
  const snapshot = JSON.parse(snapshotBytes.toString('utf8'));
  const trial = JSON.parse(readFileSync(trialPath, 'utf8'));
  if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)
      || !trial || typeof trial !== 'object' || Array.isArray(trial)) throw new Error('invalid_policy_object');
  return { mode: 'preview_only', snapshot: resolve(snapshotPath), trial: resolve(trialPath),
    snapshotSha256: actualDigest, changes: policyDiff(snapshot, trial) };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 6 || args[0] !== '--snapshot' || args[2] !== '--trial' || args[4] !== '--trusted-sha256') {
      throw new Error('invalid_preview_arguments');
    }
    const result = previewPolicyRestore({ snapshotPath: args[1], trialPath: args[3], trustedSha256: args[5] });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    const allowed = ['trusted_snapshot_required', 'distinct_policy_paths_required', 'snapshot_integrity_failed',
      'invalid_policy_object', 'unsafe_policy_key'];
    process.stderr.write(`policy_preview_aborted: ${allowed.includes(error.message) ? error.message : 'missing_or_invalid_input'}\n`);
    process.exitCode = 1;
  }
}
