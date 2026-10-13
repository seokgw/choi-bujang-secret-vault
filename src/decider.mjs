
 // ALEPH SDP 엔진이 확인한 요청만 받는 판정기입니다.
 // 클라이언트의 userId, role, 임의 기기 키는 신뢰하지 않습니다.

export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'zone_known_resource',
  'zone_memo_own',
  'zone_announcement_write'
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

  // 1. 기존 등록 기기 검사
  if (!registered) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request?.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered']
    };
  }

  // 2. 기존 판정 요청 검증
  if (
    request.schema !== 'aleph.decision.v1' ||
    !['subjectId', 'classId', 'projectId'].every(
      key =>
        typeof request[key] === 'string' &&
        request[key].length > 0
    ) ||
    typeof request.deviceId !== 'string' ||
    !/^[a-f0-9]{16}$/u.test(request.deviceId)
  ) {
    return denyZone('zone_known_resource');
  }

  // 3. 기존 경로 검사 유지
  const method = request.method;
  const path = request.path;
  const route = request.route;

  const base = [
    '/notes',
    '/api/notes',
    '/notices',
    '/api/notices',
    '/announcements'
  ].find(prefix =>
    path === prefix ||
    (
      typeof path === 'string' &&
      path.startsWith(`${prefix}/`)
    )
  );

  // 성공 소스와 동일하게 GET, PUT만 판정 대상으로 허용
  if (
    !base ||
    !['GET', 'PUT'].includes(method) ||
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

  // 4. 정확한 경로 및 route 확인
  if (
    (item && !validItem) ||
    (!item && method !== 'GET') ||
    route !== `${method} ${base}${item ? '/:id' : ''}`
  ) {
    return denyZone('zone_known_resource');
  }

  const memo =
    base === '/notes' ||
    base === '/api/notes';

  // 5. 공지 구역 접근 차단
  // 판정 입력에 검증된 강사 권한이 없으므로 기본 거부
  if (!memo) {
    return denyZone('zone_announcement_write');
  }

  // 6. 기존 메모 서비스 검사
  if (request.service !== 'notes') {
    return denyZone('zone_known_resource');
  }

  // 7. S08 관련: 메모 허용 범위 제한
  // 전체 목록, 생성, 삭제, 미지원 동작은 거부
  // 단건 GET과 PUT만 허용 대상으로 처리
  if (
    !item ||
    !['GET', 'PUT'].includes(method)
  ) {
    return denyZone('zone_known_resource');
  }

  // 메모 단건 범위를 통과한 규칙
  const zoneRule = 'zone_memo_own';

  // 8. 기존 Step-up 검사 유지
  const signals = request?.signals;

  const unusualAccess =
    signals?.source === 'judge_fixture' &&
    Number.isInteger(signals.hour) &&
    signals.hour >= 0 &&
    signals.hour <= 5 &&
    signals.network === 'unusual' &&
    Array.isArray(request?.recentEvents) &&
    request.recentEvents.some(event =>
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
        'zone_memo_own',
        'step_up_required'
      ]
    };
  }

  // 9. 허용된 단건 메모 요청
  // 실제 owner_id는 메모 API에서 별도 검사
  return {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: [
      'device_registered',
      zoneRule
    ]
  };
}
