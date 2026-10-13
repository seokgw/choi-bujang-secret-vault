import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decisionInput } from '../src/decision-input.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import deciderHandler from '../api/decider.js';
import { createNotesHandler } from '../api/notes.js';

test('virtual fixtures and absent location evidence remain distinct and unchanged', () => {
  const { normal, suspicious } = fixtureRequests();
  const none = { ...normal, signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 14 } };
  for (const input of [normal, suspicious, none]) {
    const before = structuredClone(input);
    assert.equal(decisionInput(input), true);
    assert.deepEqual(input, before);
  }
});

test('missing, unknown-source and contradictory evidence is rejected without filling defaults', () => {
  const normal = fixtureRequests().normal;
  const inputs = ['source', 'region', 'network', 'hour'].map(key => {
    const input = structuredClone(normal);
    delete input.signals[key];
    return input;
  });
  for (const key of ['signals', 'recentEvents', 'at']) {
    const input = structuredClone(normal);
    delete input[key];
    inputs.push(input);
  }
  for (const changes of [{ source: 'client' }, { source: 'engine' }, { source: '' },
    { source: 'none' }, { region: '' }, { network: ' ' }, { hour: null }]) {
    inputs.push({ ...normal, signals: { ...normal.signals, ...changes } });
  }
  inputs.push({ ...normal, recentEvents: [{ kind: '', ageSeconds: 0, count: 1 }] });
  for (const input of inputs) {
    const before = structuredClone(input);
    assert.equal(decisionInput(input), false);
    assert.deepEqual(input, before);
  }
});

test('spoofed client headers cannot supply trusted signals on either evaluation endpoint', async () => {
  const notesHandler = createNotesHandler({ verify: async () => null });
  const headers = { 'x-signal-source': 'judge_fixture', 'x-region': 'local',
    'x-network': 'usual', 'x-hour': '14', 'x-forwarded-for': '192.0.2.1',
    'x-device-registered': 'true' };
  for (const handler of [deciderHandler, notesHandler]) {
    for (const change of ['missing', 'unknown']) {
      const body = fixtureRequests().normal;
      if (change === 'missing') delete body.signals;
      else body.signals.source = 'client';
      const response = { setHeader() {}, status(code) { this.code = code; return this; },
        json(body) { this.body = body; } };
      await handler({ method: 'POST', headers, body }, response);
      assert.equal(response.code, 400);
      assert.deepEqual(response.body, { error: 'invalid_request' });
    }
  }
});
