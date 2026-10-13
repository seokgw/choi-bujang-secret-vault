import assert from 'node:assert/strict';
import config from '../aleph.config.json' with { type: 'json' };
import { fixtureRequests } from './fixture-7.mjs';

for (const registered of [true, false]) {
  const request = { ...fixtureRequests().normal, route: 'GET /api/notes',
    path: '/api/notes', deviceRegistered: registered };
  const response = await fetch(new URL('/api/notes', config.publicAppUrl), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request), redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  const result = await response.json();
  assert.equal(response.status, 200);
  assert.deepEqual(Object.keys(result).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
  assert.equal(result.requestId, request.requestId);
  assert.equal(result.decision, registered ? 'allow' : 'deny');
  assert.equal(result.reasonCode, registered ? 'approved' : 'device_not_registered');
  console.log(`deviceRegistered=${registered} → HTTP ${response.status} · ${result.decision} / ${result.reasonCode}`);
}
