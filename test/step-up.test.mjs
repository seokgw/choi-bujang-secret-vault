import assert from 'node:assert/strict';
import { test } from 'node:test';
import vm from 'node:vm';
import { decide } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

test('module and isolated function send only the combined fixture to step-up', async () => {
  for (const run of [decide, vm.runInNewContext(`(${decide.toString()})`)]) {
    const { normal, suspicious } = fixtureRequests();
    assert.equal((await run(normal)).decision, 'allow');
    const result = await run(suspicious);
    assert.equal(result.decision, 'step_up');
    assert.equal(result.reasonCode, 'step_up_required');
    assert.equal(result.requestId, suspicious.requestId);
    assert.equal(result.ruleIds.join(','), 'device_registered,step_up_required');
    assert.deepEqual(Object.keys(result).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
    const unregistered = await run({ ...suspicious, deviceRegistered: false });
    assert.equal(unregistered.decision, 'deny');
    assert.equal(unregistered.reasonCode, 'device_not_registered');
    for (const input of [
      { ...normal, signals: { ...normal.signals, region: 'foreign' } },
      { ...suspicious, signals: { ...suspicious.signals, hour: 14 } },
      { ...suspicious, signals: { ...suspicious.signals, network: 'usual' } },
      { ...suspicious, signals: { ...suspicious.signals, source: 'none' } },
      { ...suspicious, signals: undefined },
      { ...suspicious, recentEvents: undefined },
      { ...suspicious, recentEvents: [{ kind: 'risk_signal', ageSeconds: 301, count: 20 }] },
      { ...suspicious, recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 19 }] },
    ]) assert.equal((await run(input)).decision, 'allow');
    assert.equal((await run({ ...suspicious, signals: { ...suspicious.signals, region: 'local' } })).decision, 'step_up');
    assert.equal((await run({ ...suspicious, stepUp: { verified: true, authAgeSeconds: 60 } })).decision, 'allow');
    for (const age of [null, -1, 901, '60']) {
      assert.equal((await run({ ...suspicious, stepUp: { verified: true, authAgeSeconds: age } })).decision, 'step_up');
    }
  }
});
