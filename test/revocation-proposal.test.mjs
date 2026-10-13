import assert from 'node:assert/strict';
import { test } from 'node:test';
import { detect } from '../src/detect.mjs';
import { proposeDeviceRevocation } from '../src/revocation-proposal.mjs';

const origin = Date.UTC(2026, 9, 1);
const reads = n => Array.from({ length: n }, (_, i) => ({
  at: new Date(origin + i * 2000).toISOString(),
  method: 'GET',
  identity: { sub: 'learner_fixture' }
}));
const trusted = async subject => ({ verified: true, subject, deviceId: 'a'.repeat(16) });

test('burst produces proposal for exactly one separately verified virtual device', async () => {
  const actual = await proposeDeviceRevocation(detect(reads(121)), trusted);
  assert.deepEqual(actual, { action: 'propose_revocation', reasonCode: 'burst_read',
    subject: 'learner_fixture', deviceId: 'a'.repeat(16) });
});
test('normal and boundary reads never propose revocation', async () => {
  for (const n of [30, 120]) {
    assert.deepEqual(await proposeDeviceRevocation(detect(reads(n)), trusted), { action: 'observe' });
  }
});
test('missing, mismatched and unverified bindings do not identify a target', async () => {
  const alert = detect(reads(121));
  for (const lookup of [undefined, async () => null, async () => ({
    verified: false, subject: 'learner_fixture', deviceId: 'a'.repeat(16)
  }), async () => ({
    verified: true, subject: 'other_fixture', deviceId: 'a'.repeat(16)
  })]) {
    assert.deepEqual(await proposeDeviceRevocation(alert, lookup), { action: 'observe' });
  }
});
test('extra fields in a virtual incident never become a device identifier', async () => {
  const events = reads(121).map(e => ({ ...e, deviceId: 'b'.repeat(16), token: 'not-used', content: 'not-used' }));
  assert.deepEqual(await proposeDeviceRevocation(detect(events)), { action: 'observe' });
});
