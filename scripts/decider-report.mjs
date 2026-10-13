import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from './fixture-7.mjs';

export async function deciderReport() {
  const checks = [];
  for (const deviceRegistered of [true, false]) {
    const request = { ...fixtureRequests().normal, deviceRegistered,
      path: '/api/notes', route: 'GET /api/notes' };
    const result = await decide(request);
    checks.push({ deviceRegistered, decision: result.decision,
      reasonCode: result.reasonCode, ruleIds: result.ruleIds,
      passed: result.schema === 'aleph.decision.v1' && result.requestId === request.requestId
        && Object.keys(result).sort().join(',') === 'decision,reasonCode,requestId,ruleIds,schema'
        && result.decision === (deviceRegistered ? 'allow' : 'deny')
        && result.reasonCode === (deviceRegistered ? 'approved' : 'device_not_registered') });
  }
  return { schema: 'aleph.decision.v1', sourcePath: 'src/decider.mjs',
    endpoint: 'POST /api/notes', ruleIds: [...RULE_IDS], checkedAt: new Date().toISOString(),
    checks, passed: checks.every(check => check.passed),
    scope: '배포 빌드에서 실제 decide 함수를 가상 요청으로 실행한 결과' };
}
