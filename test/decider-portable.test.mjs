import assert from 'node:assert/strict';
import { test } from 'node:test';
import vm from 'node:vm';
import { decide } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const isolatedDecider = (context = {}) => vm.runInNewContext(`(${decide.toString()})`, context);

test('function-only execution allows registered reads and rejects false or absent registration', async () => {
  const standalone = isolatedDecider();
  const { normal } = fixtureRequests();
  const allowed = await standalone(normal);
  assert.equal(allowed.decision, 'allow');
  assert.equal(allowed.reasonCode, 'approved');
  assert.equal(allowed.requestId, normal.requestId);
  assert.deepEqual(Object.keys(allowed).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
  for (const value of [false, undefined, null, 'true', 1]) {
    const request = { ...normal };
    if (value === undefined) delete request.deviceRegistered;
    else request.deviceRegistered = value;
    const rejected = await standalone(request);
    assert.equal(rejected.decision, 'deny');
    assert.equal(rejected.reasonCode, 'device_not_registered');
    assert.equal(rejected.ruleIds.join(','), 'device_registered');
  }
  assert.equal((await standalone({ ...normal, method: 'POST', route: 'POST /notes' })).decision, 'deny');
});

test('existing XDR lookup still takes precedence when available', async () => {
  const { normal } = fixtureRequests();
  let observed;
  const withXdr = isolatedDecider({ activeDeny: async request => {
    observed = request;
    return { action: 'block' };
  } });
  const rejected = await withXdr(normal);
  assert.equal(observed, normal);
  assert.equal(rejected.decision, 'deny');
  assert.equal(rejected.ruleIds.join(','), 'starter.deny,xdr.brute-force.deny');
  const unregistered = await withXdr({ ...normal, deviceRegistered: false });
  assert.equal(unregistered.reasonCode, 'device_not_registered');
  assert.equal(unregistered.ruleIds.join(','), 'device_registered,xdr.brute-force.deny');
});
