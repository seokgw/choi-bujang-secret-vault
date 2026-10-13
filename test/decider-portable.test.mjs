import assert from 'node:assert/strict';
import { test } from 'node:test';
import vm from 'node:vm';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

test('module and function-only execution require exact true registration', async () => {
  assert.deepEqual(RULE_IDS, ['device_registered', 'step_up_required',
    'zone_known_resource', 'zone_announcement_write']);
  for (const run of [decide, vm.runInNewContext(`(${decide.toString()})`)]) {
    const normal = fixtureRequests().normal;
    for (const value of [true, false, undefined, null, 'true', 1]) {
      const input = { ...normal, deviceRegistered: value };
      if (value === undefined) delete input.deviceRegistered;
      const result = await run(input);
      assert.equal(result.decision, value === true ? 'allow' : 'deny');
      assert.equal(result.reasonCode, value === true ? 'approved' : 'device_not_registered');
      assert.equal(result.requestId, input.requestId);
      assert.equal(result.ruleIds.join(','), 'device_registered');
      assert.deepEqual(Object.keys(result).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
    }
    assert.equal((await run({ ...normal, method: 'POST', route: 'POST /api/notes' })).decision, 'deny');
    assert.equal((await run(undefined)).decision, 'deny');
  }
});
