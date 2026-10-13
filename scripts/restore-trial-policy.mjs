import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, realpathSync, lstatSync } from 'node:fs';
import { resolve, relative, sep } from 'node:path';
import { previewPolicyRestore, policyDiff } from './preview-policy-restore.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const own = (v, k) => Object.prototype.hasOwnProperty.call(v, k);
const isObject = v => v && typeof v === 'object' && !Array.isArray(v);
const validService = s => typeof s === 'string' && /^[a-z][a-z0-9_-]{0,39}$/.test(s);
const abort = why => { throw new Error(why); };
const contains = (root, file) => {
  const p = relative(root, file);
  return p && p !== '..' && !p.startsWith('..' + sep) && !p.startsWith(sep);
};

// Only scratch test policies may be written; never operating policies or DB.
export function planTestPolicyRestore({ snapshotPath, trialPath, trustedSha256, service }) {
  if (!validService(service)) abort('invalid_service');
  const preview = previewPolicyRestore({ snapshotPath, trialPath, trustedSha256 });
  const snapshot = JSON.parse(readFileSync(snapshotPath, 'utf8'));
  const trialBytes = readFileSync(trialPath);
  const trial = JSON.parse(trialBytes.toString('utf8'));
  if (!isObject(snapshot.services) || !isObject(trial.services)
      || !own(snapshot.services, service) || !isObject(snapshot.services[service])
      || !own(trial.services, service) || !isObject(trial.services[service])) abort('service_policy_missing');
  if (!isObject(snapshot.services[service].notesAccess)
      || !isObject(snapshot.services[service].notesAccess.ownerOnly)
      && typeof snapshot.services[service].notesAccess.ownerOnly !== 'boolean') abort('invalid_notes_access_policy');
  if (service !== 'notes' || snapshot.services.notes.notesAccess.ownerOnly !== true) abort('unsafe_notes_policy');
  const changes = policyDiff(snapshot.services[service], trial.services[service])
    .map(c => ({ ...c, path: '/services/' + service + (c.path === '/' ? '' : c.path) }));
  return { preview, snapshot, trial, trialBytes, service, changes,
    approval: hash(JSON.stringify({ sha: preview.snapshotSha256, trialSha: hash(trialBytes), service, changes })) };
}

export function restoreTestPolicy(options) {
  const { apply = false, confirm } = options;
  const plan = planTestPolicyRestore(options);
  const result = { mode: apply ? 'trial_restored' : 'preview_only',
    snapshotSha256: plan.preview.snapshotSha256,
    trialSha256: hash(plan.trialBytes), service: plan.service,
    approval: plan.approval, changes: plan.changes };
  if (!apply) return { ...result, mode: 'preview_only' };
  if (confirm !== plan.approval) abort('approval_mismatch');
  // In-place write is permitted only under a dedicated scratch directory.
  const scratch = realpathSync(resolve('artifacts/stage10-trial'));
  const trialReal = realpathSync(options.trialPath);
  if (!contains(scratch, trialReal) || !lstatSync(options.trialPath).isFile()
      || lstatSync(options.trialPath).isSymbolicLink()) abort('trial_outside_scratch');
  const latest = readFileSync(options.trialPath);
  if (hash(latest) !== hash(plan.trialBytes)) abort('trial_changed_since_preview');
  const updated = structuredClone(plan.trial);
  updated.services[plan.service] = structuredClone(plan.snapshot.services[plan.service]);
  // Audit and all other services are copied from trial unchanged.
  writeFileSync(options.trialPath, JSON.stringify(updated, null, 2) + '\n', { flag: 'w' });
  return result;
}
