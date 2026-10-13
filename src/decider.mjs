// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 등록 기기의 자료실 읽기를 허용하며 XDR 거부와 나머지 기본 거부를 보존합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
import { activeDeny, XDR_RULE_ID } from './xdr-policy.mjs';
export const RULE_IDS = Object.freeze(['starter.deny', XDR_RULE_ID, 'device_registered']);

export async function decide(request) {
  // 함수만 전달받는 실행 환경에는 서버의 파일 기반 XDR 조회가 없습니다.
  // 모듈 실행에서는 기존 조회를 그대로 사용하고, 응답 상수는 함수 안에 둡니다.
  const xdrRuleId = 'xdr.brute-force.deny';
  const starterRuleId = 'starter.deny';
  const xdr = typeof activeDeny === 'function' ? await activeDeny(request) : null;
  if (request.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: xdr ? ['device_registered', xdrRuleId] : ['device_registered'],
    };
  }
  if (!xdr && request.method === 'GET'
      && ['GET /notes', 'GET /notes/:id', 'GET /api/notes', 'GET /api/notes/:id'].includes(request.route)) {
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
    ruleIds: xdr ? [starterRuleId, xdrRuleId] : [starterRuleId],
  };
}
