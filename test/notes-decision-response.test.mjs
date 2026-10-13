import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createNotesHandler } from '../api/notes.js';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

function handlerFixture() {
  const forbidden = () => { throw Error('DB must not be used'); };
  const handler = createNotesHandler({ verify: async () => null,
    settings: forbidden, fetcher: forbidden });
  return async body => {
    const response = { setHeader() {}, status(code) { this.code = code; return this; },
      json(body) { this.body = body; } };
    await handler({ method: 'POST', headers: {}, body }, response);
    return response;
  };
}

test('POST contract returns the actual five-field decider response without accessing notes', async () => {
  const run = handlerFixture();
  for (const registered of [true, false]) {
    const request = { ...fixtureRequests().normal, deviceRegistered: registered };
    const result = await run(request);
    assert.equal(result.code, 200);
    assert.equal(result.body.decision, registered ? 'allow' : 'deny');
    assert.equal(result.body.reasonCode, registered ? 'approved' : 'device_not_registered');
    assert.equal(result.body.requestId, request.requestId);
    assert.deepEqual(Object.keys(result.body).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
  }
});

test('invalid contract rejects, while anonymous note creation still requires login', async () => {
  const run = handlerFixture();
  const normal = fixtureRequests().normal;
  for (const body of [{ ...normal, deviceRegistered: 'true' }, { ...normal, role: 'admin' },
    { ...normal, at: '2000-01-01T00:00:00.000Z' }]) {
    assert.equal((await run(body)).code, 400);
  }
  assert.equal((await run({ title: 'fictional', content: 'fictional' })).code, 401);
});
