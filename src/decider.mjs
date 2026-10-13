// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required']);

export async function decide(request) {
  const registered = request?.deviceRegistered === true;
  // Judge fixtures only: combine time, network and recent activity; region alone is not a rule.
  const signals = request?.signals;
  const unusualAccess = signals?.source === 'judge_fixture'
    && Number.isInteger(signals.hour) && signals.hour >= 0 && signals.hour <= 5
    && signals.network === 'unusual'
    && Array.isArray(request?.recentEvents)
    && request.recentEvents.some(event => event?.kind === 'risk_signal'
      && Number.isFinite(event.ageSeconds) && event.ageSeconds >= 0 && event.ageSeconds <= 300
      && Number.isSafeInteger(event.count) && event.count >= 20);
  // This is an engine-provided verification result, not a browser header or a login bypass.
  const verified = request?.stepUp?.verified === true
    && Number.isFinite(request.stepUp.authAgeSeconds)
    && request.stepUp.authAgeSeconds >= 0 && request.stepUp.authAgeSeconds <= 900;
  if (registered && unusualAccess && !verified) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request?.requestId,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['device_registered', 'step_up_required'],
    };
  }
  return {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision: registered ? 'allow' : 'deny',
    reasonCode: registered ? 'approved' : 'device_not_registered',
    ruleIds: ['device_registered'],
  };
}
