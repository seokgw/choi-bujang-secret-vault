import assert from 'node:assert/strict';
import config from '../aleph.config.json' with { type: 'json' };
import { fixtureRequests } from './fixture-7.mjs';
import { RULE_IDS } from '../src/decider.mjs';

// Student hypothesis check, not an implementation of the operator's judge.
const manifestResponse = await fetch(new URL('/aleph.json', config.publicAppUrl), {
  redirect: 'error', signal: AbortSignal.timeout(10000), cache: 'no-store',
});
assert.equal(manifestResponse.status, 200, '배포 증명 조회 실패');
const manifest = await manifestResponse.json();
assert.equal(manifest.schema, 'aleph.defense.deployment.v1');
assert.equal(manifest.step, config.step);
assert.ok(manifest.allowedRoutes?.includes('POST /api/decider'), '판정 API 경로 누락');
assert.deepEqual(manifest.policyRules, [...RULE_IDS], '배포 규칙과 로컬 RULE_IDS 불일치');
assert.ok(manifest.policyRules.includes('device_registered'), '기기 규칙 누락');
console.log('배포 기록 확인 → POST /api/decider · policyRules: device_registered');

for (const registered of [true, false]) {
  const clock = await fetch(new URL('/api/decider', config.publicAppUrl), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  const serverTime = Date.parse(clock.headers.get('date'));
  await clock.arrayBuffer();
  assert(Number.isFinite(serverTime), '서버 시각 헤더 확인 필요');
  const request = { ...fixtureRequests().normal, route: 'GET /api/notes',
    path: '/api/notes', deviceRegistered: registered, at: new Date(serverTime).toISOString() };
  const response = await fetch(new URL('/api/decider', config.publicAppUrl), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request), redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  const result = await response.json();
  assert.equal(response.status, 200);
  assert.deepEqual(Object.keys(result).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
  assert.equal(result.requestId, request.requestId);
  assert.equal(result.decision, registered ? 'allow' : 'deny');
  assert.equal(result.reasonCode, registered ? 'approved' : 'device_not_registered');
  assert.ok(result.ruleIds.includes('device_registered'));
  console.log(`deviceRegistered=${registered} → HTTP ${response.status} · ${result.decision} / ${result.reasonCode}`);
}
console.log('학생의 가상 요청 HTTP 점검이며 운영 심판 판정이 아닙니다.');
