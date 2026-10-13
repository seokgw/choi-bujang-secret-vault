// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
import { decide } from './decider.mjs';
import { detect } from './detect.mjs';
import { checkDetection } from '../scripts/detect-test.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

export async function runAttackChecks(config) {
  if (![1, 2, 3, 4, 5, 6, 7, 8, 9].includes(config.step)) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  if (config.step >= 2) {
    const checks = [
      ['/data.json', 'static_note_removal', '404 또는 제목·본문이 없는 빈 notes 배열'],
      ['/api/notes', config.step >= 3 ? 'anonymous_note_rejection' : 'public_api_direct_request', config.step >= 3 ? '401 또는 403 JSON 오류; 자료와 내부 정보 없음' : '현재 단계는 인증 없이 직접 호출 가능; 정상 설정 시 가상 메모 4건'],
      ['/aleph.json', 'deployment_identity', `현재 ${config.step}단계 배포 증명 JSON 제공`],
      ['/', 'homepage_nosniff', '첫 화면에 X-Content-Type-Options: nosniff'],
    ];
    if (config.step >= 4) checks.push(['/api/notes/1', 'anonymous_detail_rejection',
      '401 또는 403 JSON 오류; 상세 경로도 비로그인 자료 반환 없음']);
    if (config.step >= 8) checks.push(['/api/notices/1', 'anonymous_notice_rejection',
      '401 JSON 오류; 비로그인 공지 자료 반환 없음']);
    const results = [];
    for (const [path, attackId, expected] of checks) {
      let observed;
      try {
        const res = await fetch(new URL(path, app), {
          redirect: 'error', signal: AbortSignal.timeout(10000),
        });
        if (path === '/') {
          observed = `HTTP ${res.status}; nosniff ${res.headers.get('x-content-type-options') === 'nosniff' ? '확인' : '미확인'}`;
        } else if (path === '/data.json' && res.status === 404) {
          observed = 'HTTP 404 확인';
        } else {
          let data;
          try { data = await res.json(); } catch { /* Only report shape/status. */ }
          if (path === '/data.json') {
            observed = `HTTP ${res.status}; 빈 notes 배열 ${Array.isArray(data?.notes) && data.notes.length === 0 ? '확인' : '미확인'}`;
          } else if (path.startsWith('/api/notes') || path.startsWith('/api/notices')) {
            observed = config.step >= 3
              ? `비로그인 HTTP ${res.status}; JSON 오류 ${[401, 403].includes(res.status) && res.headers.get('content-type')?.includes('application/json') && data && Object.keys(data).length === 1 && ['unauthorized', 'forbidden'].includes(data.error) ? '확인' : '미확인'}`
              : `인증 없는 직접 요청 HTTP ${res.status}; 메모 건수 ${Array.isArray(data?.notes) ? data.notes.length : '미확인'}`;
          } else {
            observed = `HTTP ${res.status}; ${config.step}단계 증명 ${data?.schema === 'aleph.defense.deployment.v1' && data.step === config.step ? '확인' : '미확인'}${config.step >= 5 ? `; 원본 주소 ${data?.originalApiUrl === config.originalApiUrl ? '확인' : '미확인'}` : ''}`;
          }
        }
      } catch {
        observed = '요청 시도했으나 응답을 확인하지 못함; 사용자 확인 필요';
      }
      results.push({ attackId, expected, observed });
    }
    if (config.step >= 6) {
      const { normal } = fixtureRequests();
      const missing = { ...normal };
      delete missing.deviceRegistered;
      for (const [attackId, request, decision, reasonCode] of [
        ['registered_device_local', normal, 'allow', 'approved'],
        ['unregistered_device_local', { ...normal, deviceRegistered: false }, 'deny', 'device_not_registered'],
        ['missing_device_registration_local', missing, 'deny', 'device_not_registered'],
      ]) {
        const result = await decide(request);
        results.push({ attackId, expected: `가상 요청 연습: ${decision} / ${reasonCode}`,
          observed: `로컬 decide 호출: ${result.decision} / ${result.reasonCode}; ${result.decision === decision && result.reasonCode === reasonCode ? '일치' : '불일치'}; 실제 심판 판정 아님` });
      }
      results.push({ attackId: 'unregistered_device_judge',
        expected: '실제 미등록 기기 공격은 심판이 담당',
        observed: '미실행; 학생의 실제 미등록 기기 공격·심판 판정은 확인하지 않음' });
      results.push({ attackId: 'registered_device_live',
        expected: '등록 기기로 로그인 후 자기 자료실 읽기',
        observed: '미실행; 6단계 실제 등록 기기 접속·운영 연결은 확인하지 않음' });
    }
    if (config.step >= 7) {
      const { normal, suspicious } = fixtureRequests();
      for (const [attackId, request, expected] of [
        ['normal_access_local', normal, 'allow'],
        ['combined_risk_local', suspicious, 'step_up'],
        ['verified_step_up_local', { ...suspicious, stepUp: { verified: true, authAgeSeconds: 60 } }, 'allow'],
      ]) {
        const result = await decide(request);
        results.push({ attackId, expected: `가상 요청 연습: ${expected}`,
          observed: `로컬 decide: ${result.decision} / ${result.reasonCode}; ${result.decision === expected ? '일치' : '불일치'}; 실제 재로그인·심판 판정 아님` });
      }
      results.push({ attackId: 'relogin_gate_live', expected: '같은 주체의 새 로그인 검증 후 요청 재판정',
        observed: '미실행; 제공 엔진의 동일 주체·새 로그인 시각 전달 연결 미확인으로 실제 자료 차단·재허용을 시험하지 않음' });
    }
    if (config.step >= 8) {
      results.push({ attackId: 'resource_zone_live', expected: '자기 메모 허용·타인 메모 거부·학생 공지 수정 거부',
        observed: '미실행; 실제 계정·저장 강사 권한을 사용한 HTTP 실측 없음. 비로그인 HTTP 점검·API 모의 시험·DB 롤백 시험과 구분' });
    }
    if (config.step >= 9) {
      const checks = await checkDetection(detect);
      const passed = checks.filter(item => item.passed).length;
      results.push({
        attackId: 'burst_read_detection_local',
        expected: '가상 사건 6개: 정상·경계값·분리·분산 observe, 폭주 121·200건 propose_revocation',
        observed: `탐지 연습 ${passed}/${checks.length}개 통과; 실제 회수·심판 판정 아님`
      });
      results.push({
        attackId: 'verified_device_revocation_live',
        expected: '확인된 가상 기기 1개에만 회수 제안, 정상 기기는 유지',
        observed: '미실행; 엔진 검증 기기 바인딩 및 실제 회수·시간 측정 연결 없음'
      });
    }
    return results;
  }
  const response = await fetch(new URL('/data.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let visible = false;
  if (response.ok) {
    try {
      const data = await response.json();
      visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
        && data.notes.length > 0;
    } catch {
      // A non-JSON response is a failed check, not a successful deployment.
    }
  }
  return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
    observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
}
