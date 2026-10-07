// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// XDR의 신뢰된 주체 연결 규칙을 추가로 확인하며 기존 기본 거부를 보존합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
import { activeDeny, XDR_RULE_ID } from './xdr-policy.mjs';
export const RULE_IDS = Object.freeze(['starter.deny', XDR_RULE_ID]);

export async function decide(request) {
  const xdr = await activeDeny(request);
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'deny',
    reasonCode: 'starter_not_ready',
    ruleIds: xdr ? [RULE_IDS[0], XDR_RULE_ID] : [RULE_IDS[0]],
  };
}
