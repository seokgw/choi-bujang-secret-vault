// 9단계 탐지 입력: 엔진이 검증해 전달한 가상 사건만 사용합니다.
// 현재 docs/DETECT_EVENTS.md의 사건에는 at, method, identity.sub만 있습니다.
// 기기와 판정은 계약에 없으므로 임의 필드·브라우저 헤더에서 추측하지 않습니다.
// 메모 내용, 토큰, 실명 등 추가 필드는 읽거나 기록하거나 반환하지 않습니다.
const PSEUDONYM = /^[a-z][a-z0-9_-]{0,79}$/u;

export function readDetectionEvents(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  return events.map(event => {
    const sub = event?.identity?.sub;
    const method = event?.method;
    const at = event?.at;

    if (typeof sub !== 'string' || !PSEUDONYM.test(sub)
        || typeof method !== 'string' || !/^[A-Z]{3,10}$/u.test(method)
        || typeof at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(at)
        || !Number.isFinite(Date.parse(at))) {
      throw new TypeError('invalid_detection_event');
    }

    // 10분 조회 판단에 필요한 시각은 유지합니다.
    // deviceId/decision은 제공된 계약에 없어서 unknown(null)입니다.
    return { at, subject: sub, deviceId: null, method, decision: null };
  });
}

export function detect(events) {
  // 입력만 정리합니다. 탐지 임계값·권한 회수 제안은 아직 구현하지 않습니다.
  readDetectionEvents(events);
  return { action: 'observe' };
}
