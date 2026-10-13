import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { previewPolicyRestore } from '../scripts/preview-policy-restore.mjs';

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'policy-preview-'));
  const snapshotPath = join(dir, 'snapshot.json');
  const trialPath = join(dir, 'trial.json');
  const snapshot = JSON.stringify({ revision: 7, deny: { export: true, delete: true }, keep: 'safe' });
  const trial = JSON.stringify({ revision: 8, deny: { export: false }, keep: 'safe', extra: true });
  writeFileSync(snapshotPath, snapshot); writeFileSync(trialPath, trial);
  return { snapshotPath, trialPath, trustedSha256: createHash('sha256').update(snapshot).digest('hex'), snapshot, trial };
}
test('preview reports changed paths without modifying either policy file', () => {
  const f = fixture();
  const result = previewPolicyRestore(f);
  assert.equal(result.mode, 'preview_only');
  assert.deepEqual(result.changes, [
    { path: '/deny/delete', change: 'restore_missing' },
    { path: '/deny/export', change: 'restore_value' },
    { path: '/extra', change: 'remove_trial_only' },
    { path: '/revision', change: 'restore_value' }
  ]);
  assert.equal(readFileSync(f.snapshotPath, 'utf8'), f.snapshot);
  assert.equal(readFileSync(f.trialPath, 'utf8'), f.trial);
});
test('missing snapshot, missing trusted hash or verification failure aborts', () => {
  const f = fixture();
  assert.throws(() => previewPolicyRestore({ ...f, trustedSha256: '' }), /trusted_snapshot_required/);
  assert.throws(() => previewPolicyRestore({ ...f, trustedSha256: '0'.repeat(64) }), /snapshot_integrity_failed/);
  assert.throws(() => previewPolicyRestore({ ...f, snapshotPath: join(f.snapshotPath, 'missing') }), /ENOENT|ENOTDIR/);
  assert.throws(() => previewPolicyRestore({ ...f, trialPath: f.snapshotPath }), /distinct_policy_paths_required/);
});
