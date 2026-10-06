// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (![1, 2, 3].includes(config.step)) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
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
      ['/api/notes', config.step === 3 ? 'anonymous_note_rejection' : 'public_api_direct_request', config.step === 3 ? '401 또는 403 JSON 오류; 자료와 내부 정보 없음' : '현재 단계는 인증 없이 직접 호출 가능; 정상 설정 시 가상 메모 4건'],
      ['/aleph.json', 'deployment_identity', `현재 ${config.step}단계 배포 증명 JSON 제공`],
      ['/', 'homepage_nosniff', '첫 화면에 X-Content-Type-Options: nosniff'],
    ];
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
          } else if (path === '/api/notes') {
            observed = config.step === 3
              ? `비로그인 HTTP ${res.status}; JSON 오류 ${[401, 403].includes(res.status) && res.headers.get('content-type')?.includes('application/json') && data && Object.keys(data).length === 1 && ['unauthorized', 'forbidden'].includes(data.error) ? '확인' : '미확인'}`
              : `인증 없는 직접 요청 HTTP ${res.status}; 메모 건수 ${Array.isArray(data?.notes) ? data.notes.length : '미확인'}`;
          } else {
            observed = `HTTP ${res.status}; ${config.step}단계 증명 ${data?.schema === 'aleph.defense.deployment.v1' && data.step === config.step ? '확인' : '미확인'}`;
          }
        }
      } catch {
        observed = '요청 시도했으나 응답을 확인하지 못함; 사용자 확인 필요';
      }
      results.push({ attackId, expected, observed });
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
