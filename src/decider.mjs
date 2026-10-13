// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required',
  'zone_known_resource']);

export async function decide(request) {
  const registered = request?.deviceRegistered === true;
  const denyZone = ruleId => ({ schema: 'aleph.decision.v1', requestId: request?.requestId,
    decision: 'deny', reasonCode: 'starter_not_ready', ruleIds: ['device_registered', ruleId] });
  if (!registered) {
    return { schema: 'aleph.decision.v1', requestId: request?.requestId,
      decision: 'deny', reasonCode: 'device_not_registered', ruleIds: ['device_registered'] };
  }
  if (request.schema !== 'aleph.decision.v1'
      || !['subjectId', 'classId', 'projectId'].every(key => typeof request[key] === 'string' && request[key].length > 0)
      || typeof request.deviceId !== 'string' || !/^[a-f0-9]{16}$/u.test(request.deviceId)) {
    return denyZone('zone_known_resource');
  }
  // No path normalization, wildcard suffixes, query-selected actions or client roles.
  // Use only the engine's method + concrete path + canonical route together.
  const method = request.method;
  const path = request.path;
  const route = request.route;
  const base = ['/notes', '/api/notes', '/notices', '/api/notices', '/announcements']
    .find(prefix => path === prefix || typeof path === 'string' && path.startsWith(`${prefix}/`));
  if (!base || !['GET', 'PUT', 'PATCH'].includes(method) || request.queryLength !== 0) {
    return denyZone('zone_known_resource');
  }
  const item = path !== base;
  const suffix = item ? path.slice(base.length + 1) : '';
  // Engine resource IDs are opaque: do not impose the database's integer ID format.
  const functionNames = ['export', 'import', 'search', 'share', 'bulk', 'all', 'admin',
    'download', 'publish', 'new', 'list', 'count', 'stats', 'backup', 'restore', 'archive'];
  const validItem = /^[A-Za-z0-9_-]{1,128}$/u.test(suffix)
    && !functionNames.includes(suffix.toLowerCase());
  if ((item && !validItem) || (!item && method !== 'GET')
      || route !== `${method} ${base}${item ? '/:id' : ''}`) {
    return denyZone('zone_known_resource');
  }
  const memo = base === '/notes' || base === '/api/notes';
  if (memo && request.service !== 'notes') return denyZone('zone_known_resource');
  // Resource ownership and instructor authorization remain enforced by the data APIs.
  // This decider currently does not distinguish those permissions.
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
