// 9단계 탐지기는 엔진이 검증해 넘긴 가상 사건만 처리합니다.
// 메모 본문·실명·토큰 또는 계약 밖의 필드는 읽거나 기록하지 않습니다.
const PSEUDONYM = /^[a-z][a-z0-9_-]{0,79}$/u;
const WINDOW_MS = 10 * 60 * 1000;
const READ_LIMIT = 120;

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
    return { at, subject: sub, deviceId: null, method, decision: null };
  });
}

export function detect(events) {
  const readsBySubject = new Map();
  for (const event of readDetectionEvents(events)) {
    if (event.method !== 'GET') continue;
    const times = readsBySubject.get(event.subject) ?? [];
    times.push(Date.parse(event.at));
    readsBySubject.set(event.subject, times);
  }

  // 각 가명 사용자의 어느 10분 구간에서든 121번째 GET을 확인합니다.
  // 사용자별로 분리하며 입력 순서와 무관하게 검사합니다.
  let earliest = null;
  for (const [subject, times] of readsBySubject) {
    times.sort((a, b) => a - b);
    for (let end = READ_LIMIT; end < times.length; end++) {
      if (times[end] - times[end - READ_LIMIT] <= WINDOW_MS) {
        const candidate = { subject, at: times[end] };
        if (!earliest || candidate.at < earliest.at
            || (candidate.at === earliest.at && subject < earliest.subject)) earliest = candidate;
        break;
      }
    }
  }
  return earliest
    ? { action: 'propose_revocation', reasonCode: 'burst_read', subject: earliest.subject }
    : { action: 'observe' };
}
