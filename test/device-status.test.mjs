import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createDeviceStatusHandler } from '../api/device-status.js';

function response() {
  return { headers: {}, setHeader(k, v) { this.headers[k] = v; },
    status(n) { this.code = n; return this; },
    json(body) { this.body = body; return this; } };
}
test('GET reports unverified even for a logged-in user', async () => {
  const handler = createDeviceStatusHandler({ verify: async () => ({ userId: 'fixture-user' }) });
  const res = response();
  await handler({ method: 'GET' }, res);
  assert.equal(res.code, 200);
  assert.deepEqual(res.body, { deviceApproval: 'unverified', trusted: false });
  assert.equal(res.headers['Cache-Control'], 'no-store');
});
test('anonymous request is rejected', async () => {
  const handler = createDeviceStatusHandler({ verify: async () => null });
  const res = response();
  await handler({ method: 'GET' }, res);
  assert.equal(res.code, 401);
  assert.deepEqual(res.body, { error: 'unauthorized' });
});
test('non-GET method is rejected without calling verifier', async () => {
  const handler = createDeviceStatusHandler({ verify: async () => { throw Error('should not verify'); } });
  const res = response();
  await handler({ method: 'POST' }, res);
  assert.equal(res.code, 405);
  assert.equal(res.headers.Allow, 'GET');
});
