// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
import { decide } from './decider.mjs';
import { detect } from './detect.mjs';
import { checkDetection } from '../scripts/detect-test.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { observePublicChecks } from './http-checks.mjs';

export async function runAttackChecks(config, options = {}) {
  if (![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].includes(config.step)) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
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
    const results = await observePublicChecks(config, options);
    // The judge correlates every submitted attackId with a real request log.
    // Local fixtures and planned exercises are not HTTP evidence.
    const planned = [
      ['homepage_nosniff', '첫 화면 보안 응답 헤더 확인'],
      ['anonymous_detail_rejection', '비로그인 단건 메모 거부'],
      ['anonymous_notice_rejection', '비로그인 단건 공지 거부'],
      ['registered_device_local', '등록 기기의 정상 요청 허용'],
      ['unregistered_device_local', '미등록 기기 거부'],
      ['missing_device_registration_local', '기기 등록 정보 없는 요청 거부'],
      ['registered_device_live', '등록 기기의 실제 자료 접근'],
      ['normal_access_local', '정상 접근 허용'],
      ['combined_risk_local', '복합 위험의 추가 인증'],
      ['verified_step_up_local', '검증된 추가 인증 후 허용'],
      ['resource_zone_live', '본인 메모 허용과 타인 메모·공지 변경 거부'],
      ['burst_read_detection_local', '가상 대량 조회 탐지'],
      ['verified_policy_restore_live', '검증 사본으로 정책 복원'],
      ['verified_single_note_restore_live', '검증 사본으로 단건 복원'],
      ['stage1_to_9_after_restore_live', '복구 후 정상·금지 요청 확인'],
      ['pwa_device_approval_live', '승인 기기 정상 허용과 미승인 거부'],
      ['total_assault_41_live', '41종 공격 전체 방어']
    ];
    for (const [attackId, expected] of planned) {
      results.push({ attackId, expected, observed: 'not_run' });
    }
    // Three actual HTTP observations and seventeen unexecuted scenarios.
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
