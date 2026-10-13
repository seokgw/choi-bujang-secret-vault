import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createNotesHandler } from '../api/notes.js';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

function fixture(options = {}) {
  let dbCalls = 0;
  const handler = createNotesHandler({
    verify: async () => ({ userId: 'fixture-owner' }), deny: async () => false,
    settings: () => ({ key: 'test-only-placeholder', url: new URL('https://test.supabase.co') }),
    fetcher: async () => { dbCalls++; return Response.json([]); }, ...options,
  });
  return { dbCalls: () => dbCalls, run: async (request = {}) => {
    const response = { setHeader() {}, status(code) { this.code = code; return this; },
      json(body) { this.body = body; } };
    await handler({ method: 'GET', headers: {}, query: {}, ...request }, response);
    return response;
  } };
}

test('authenticated reads without verified engine input reject before DB, including spoofed fields', async () => {
  for (const detailRoute of [false, true]) {
    const f = fixture({ detailRoute });
    const r = await f.run({ headers: { 'x-device-registered': 'true' },
      body: { deviceRegistered: true }, query: { id: '1', deviceRegistered: true },
      deviceRegistered: true });
    assert.equal(r.code, 403);
    assert.deepEqual(r.body, { error: 'forbidden' });
    assert.equal(f.dbCalls(), 0);
  }
});

test('server-provided contract calls real decider: registered allow, false and missing deny', async () => {
  for (const value of [true, false, undefined]) {
    const input = { ...fixtureRequests().normal, route: 'GET /api/notes', path: '/api/notes' };
    if (value === undefined) delete input.deviceRegistered;
    else input.deviceRegistered = value;
    const f = fixture({ verifiedDecisionRequest: async () => input });
    const r = await f.run();
    assert.equal(r.code, value === true ? 200 : 403);
    assert.equal(f.dbCalls(), value === true ? 1 : 0);
  }
});

test('anonymous, XDR rejection and engine failure stay closed', async () => {
  for (const [options, status] of [
    [{ verify: async () => null }, 401],
    [{ deny: async () => true }, 403],
    [{ verifiedDecisionRequest: async () => { throw Error('fixture failure'); } }, 403],
    [{ verifiedDecisionRequest: async () => ({ ...fixtureRequests().normal, route: 'GET /api/notes' }),
      decideRequest: async () => ({ decision: 'allow', requestId: 'wrong' }) }, 403],
  ]) {
    const f = fixture(options);
    assert.equal((await f.run()).code, status);
    assert.equal(f.dbCalls(), 0);
  }
});

test('existing write path does not invoke the new read-only decision gate', async () => {
  const f = fixture({ verifiedDecisionRequest: async () => { throw Error('must not run'); } });
  const r = await f.run({ method: 'POST', headers: { authorization: 'test-only-header' },
    body: { title: 'fictional test', content: 'fictional test' } });
  assert.equal(r.code, 201);
  assert.equal(f.dbCalls(), 1);
});
