import assert from 'node:assert/strict';
import { test } from 'node:test';
import handler from '../api/decider.js';
import config from '../aleph.config.json' with { type: 'json' };
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';

async function call(method, body) {
  const response = { headers: {}, setHeader(key, value) { this.headers[key] = value; },
    status(code) { this.code = code; return this; }, json(body) { this.body = body; } };
  await handler({ method, body }, response);
  return response;
}

test('registered and unregistered POST fixtures return actual five-field decisions', async () => {
  for (const registered of [true, false]) {
    const input = { ...fixtureRequests().normal, deviceRegistered: registered };
    const response = await call('POST', input);
    assert.equal(response.code, 200);
    assert.equal(response.body.requestId, input.requestId);
    assert.equal(response.body.decision, registered ? 'allow' : 'deny');
    assert.equal(response.body.reasonCode, registered ? 'approved' : 'device_not_registered');
    assert.ok(response.body.ruleIds.includes('device_registered'));
    assert.deepEqual(Object.keys(response.body).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
    assert.equal(response.headers['Cache-Control'], 'no-store');
  }
});

test('decider endpoint rejects unsupported methods and malformed contracts', async () => {
  const input = fixtureRequests().normal;
  for (const method of ['GET', 'PUT', 'DELETE']) {
    const response = await call(method, input);
    assert.equal(response.code, 405);
    assert.equal(response.headers.Allow, 'POST');
  }
  for (const body of [null, '{', { ...input, deviceRegistered: 'true' },
    { ...input, role: 'admin' }, { ...input, at: '2000-01-01T00:00:00.000Z' }]) {
    assert.equal((await call('POST', body)).code, 400);
  }
});

test('deployment identity lists the dedicated route without a decider report', () => {
  const identity = deploymentIdentity({ VERCEL_GIT_PROVIDER: 'github',
    VERCEL_GIT_REPO_OWNER: 'fixture', VERCEL_GIT_REPO_SLUG: 'fixture',
    VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40), VERCEL_URL: 'fixture.vercel.app' }, config);
  assert.ok(identity.allowedRoutes.includes('POST /api/decider'));
  assert.ok(identity.allowedRoutes.includes('POST /api/session'));
  assert.ok(identity.allowedRoutes.includes('GET /api/notes'));
  assert.equal(Object.hasOwn(identity, 'decider'), false);
});
