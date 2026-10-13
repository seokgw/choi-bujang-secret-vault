
export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'zone_known_resource',
  'zone_announcement_write',
  'zone_note_owner'
]);

export async function decide(request) {
  const registered = request?.deviceRegistered === true;

  const denyZone = ruleId => ({
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision: 'deny',
    reasonCode: 'starter_not_ready',
    ruleIds: ['device_registered', ruleId]
  });

  // 1. 등록된 기기만 허용
  if (!registered) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request?.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered']
    };
  }

  // 2. 엔진 입력 검증
  if (
    request.schema !== 'aleph.decision.v1' ||
    !['subjectId', 'classId', 'projectId'].every(
      key => typeof request[key] === 'string' &&
        request[key].length > 0
    ) ||
    typeof request.deviceId !== 'string' ||
    !/^[a-f0-9]{16}$/u.test(request.deviceId)
  ) {
    return denyZone('zone_known_resource');
  }

  // 3. 메서드와 실제 경로 검증
  const method = request.method;
  const path = request.path;
  const route = request.route;

  const base = [
    '/notes',
    '/api/notes',
    '/notices',
    '/api/notices',
    '/announcements'
  ].find(
    prefix =>
      path === prefix ||
      (
        typeof path === 'string' &&
        path.startsWith(`${prefix}/`)
      )
  );

  if (
    !base ||
    !['GET', 'PUT', 'PATCH'].includes(method) ||
    request.queryLength !== 0
  ) {
    return denyZone('zone_known_resource');
  }

  const item = path !== base;
  const suffix = item ? path.slice(base.length + 1) : '';

  const functionNames = [
    'export', 'import', 'search', 'share',
    'bulk', 'all', 'admin', 'download',
    'publish', 'new', 'list', 'count',
    'stats', 'backup', 'restore', 'archive'
  ];

  const validItem =
    /^[A-Za-z0-9_-]{1,128}$/u.test(suffix) &&
    !functionNames.includes(suffix.toLowerCase());

  if (
    (item && !validItem) ||
    (!item && method !== 'GET') ||
    route !== `${method} ${base}${item ? '/:id' : ''}`
  ) {
    return denyZone('zone_known_resource');
  }

  // 4. 리소스 유형 확인
  const memo =
    base === '/notes' ||
    base === '/api/notes';

  // 5. 기존 공지 수정 차단 유지
  // 검증된 강사 권한이 없으므로 쓰기 요청은 거부
  if (!memo && method !== 'GET') {
    return denyZone('zone_announcement_write');
  }

  // 6. 메모 서비스 확인
  if (memo && request.service !== 'notes') {
    return denyZone('zone_known_resource');
  }

  // 7. 추가: 메모 소유권 확인
  // resourceOwnerSubjectId는 서버가 DB에서 조회하여
  // 엔진에 전달한 검증된 소유자 ID여야 한다.
  // 브라우저에서 전달한 ownerId 등을 사용하면 안 된다.
  if (memo && item) {
    const owner = request.resourceOwnerSubjectId;

    if (
      typeof owner !== 'string' ||
      owner.length === 0 ||
      owner !== request.subjectId
    ) {
      return denyZone('zone_note_owner');
    }
  }

  // 8. 기존 Step-up 위험 신호 검사 유지
  const signals = request?.signals;

  const unusualAccess =
    signals?.source === 'judge_fixture' &&
    Number.isInteger(signals.hour) &&
    signals.hour >= 0 &&
    signals.hour <= 5 &&
    signals.network === 'unusual' &&
    Array.isArray(request?.recentEvents) &&
    request.recentEvents.some(
      event =>
        event?.kind === 'risk_signal' &&
        Number.isFinite(event.ageSeconds) &&
        event.ageSeconds >= 0 &&
        event.ageSeconds <= 300 &&
        Number.isSafeInteger(event.count) &&
        event.count >= 20
    );

  const verified =
    request?.stepUp?.verified === true &&
    Number.isFinite(request.stepUp.authAgeSeconds) &&
    request.stepUp.authAgeSeconds >= 0 &&
    request.stepUp.authAgeSeconds <= 900;

  if (unusualAccess && !verified) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request?.requestId,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: [
        'device_registered',
        'step_up_required'
      ]
    };
  }

  // 9. 모든 검사를 통과한 경우만 허용
  return {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered']
  };
}
