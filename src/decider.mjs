// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 등록 기기의 자료실 읽기를 허용하며 XDR 거부와 나머지 기본 거부를 보존합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
import { activeDeny, XDR_RULE_ID } from './xdr-policy.mjs';
export const RULE_IDS = Object.freeze(['starter.deny', XDR_RULE_ID, 'device_registered']);

export async function decide(request) {
  const xdr = await activeDeny(request);
  if (request.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: xdr ? ['device_registered', XDR_RULE_ID] : ['device_registered'],
    };
  }
  if (!xdr && request.service === 'notes' && request.method === 'GET'
      && ['GET /notes', 'GET /notes/:id'].includes(request.route)) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'allow',
      reasonCode: 'approved',
      ruleIds: ['device_registered'],
    };
  }
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'deny',
    reasonCode: 'starter_not_ready',
    ruleIds: xdr ? [RULE_IDS[0], XDR_RULE_ID] : [RULE_IDS[0]],
  };
}
