import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { restoreTestPolicy } from '../scripts/restore-trial-policy.mjs';

test('preview then restore only notes policy; preserve other service and audit', () => {
  const dir = mkdtempSync(join(tmpdir(), 'stage10-test-'));
  const snapshotPath = join(dir, 'verified.json');
  const scratch = join(process.cwd(), 'artifacts', 'stage10-trial');
  mkdirSync(scratch, { recursive: true });
  const trialPath = join(scratch, 'trial-test-' + process.pid + '.json');
  const verified = JSON.stringify({ version: 3, services: {
    notes: { notesAccess: { ownerOnly: true } },
    other: { allow: true } }, audit: [{ event: 'original' }] });
  const trial = { version: 4, services: {
    notes: { notesAccess: { ownerOnly: false } },
    other: { allow: false } }, audit: [{ event: 'preserve' }] };
  writeFileSync(snapshotPath, verified);
  writeFileSync(trialPath, JSON.stringify(trial));
  const options = { snapshotPath, trialPath, trustedSha256: createHash('sha256').update(verified).digest('hex'), service: 'notes' };
  const prior = readFileSync(trialPath, 'utf8');
  const preview = restoreTestPolicy(options);
  assert.equal(preview.mode, 'preview_only');
  assert.deepEqual(preview.changes, [{ path: '/services/notes/notesAccess/ownerOnly', change: 'restore_value' }]);
  assert.equal(readFileSync(trialPath, 'utf8'), prior);
  assert.throws(() => restoreTestPolicy({ ...options, apply: true, confirm: 'bad' }), /approval_mismatch/);
  restoreTestPolicy({ ...options, apply: true, confirm: preview.approval });
  const restored = JSON.parse(readFileSync(trialPath, 'utf8'));
  assert.equal(restored.services.notes.notesAccess.ownerOnly, true);
  assert.deepEqual(restored.services.other, trial.services.other);
  assert.deepEqual(restored.audit, trial.audit);
  const canRead = (requester, owner) => !restored.services.notes.notesAccess.ownerOnly || requester === owner;
  assert.equal(canRead('b_fixture', 'a_fixture'), false);
  assert.equal(canRead('a_fixture', 'a_fixture'), true);
});

test('refuse invalid or missing trusted snapshot', () => {
  assert.throws(() => restoreTestPolicy({ snapshotPath: '/missing', trialPath: '/missing2', service: 'notes' }), /trusted_snapshot_required/);
});
