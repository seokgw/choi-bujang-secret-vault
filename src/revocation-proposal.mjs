// 9단계: 탐지 결과와 신뢰된 엔진의 기기 바인딩을 분리합니다.
// 브라우저 이벤트에 포함된 임의 deviceId, role 또는 토큰을 사용하지 않습니다.
// 이 함수는 제안 객체만 만들며 기기 회수나 API 호출은 하지 않습니다.
const DEVICE_ID = /^[0-9a-f]{16}$/u;

export async function proposeDeviceRevocation(detection, lookupVerifiedDevice) {
  if (detection?.action !== 'propose_revocation'
      || detection?.reasonCode !== 'burst_read'
      || typeof detection.subject !== 'string'
      || !/^[a-z][a-z0-9_-]{0,79}$/u.test(detection.subject)) {
    return { action: 'observe' };
  }
  // 운영 엔진이 확인한 바인딩을 반환하는 서버 전용 함수가 필요합니다.
  // 제공되지 않았거나 바인딩이 불명확하면 특정 기기를 추측하지 않습니다.
  if (typeof lookupVerifiedDevice !== 'function') return { action: 'observe' };
  const record = await lookupVerifiedDevice(detection.subject);
  if (!record || record.subject !== detection.subject
      || record.verified !== true
      || typeof record.deviceId !== 'string' || !DEVICE_ID.test(record.deviceId)) {
    return { action: 'observe' };
  }
  return {
    action: 'propose_revocation',
    reasonCode: detection.reasonCode,
    subject: detection.subject,
    deviceId: record.deviceId
  };
}
