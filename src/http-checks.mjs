import { randomUUID } from 'node:crypto';

// Direct HTTP observations only; never a judge verdict or stored-log attestation.
export async function observePublicChecks(config, { fetcher = fetch,
  makeId = randomUUID, now = () => new Date().toISOString() } = {}) {
  const probes = [
    ['static_note_removal', '/data.json', '공개 메모 파일 요청은 HTTP 404'],
    ['anonymous_note_rejection', '/api/notes', '비로그인 요청은 HTTP 401/403 JSON 오류'],
    ['deployment_identity', '/aleph.json', '정상 공개 요청은 HTTP 200 배포 식별 JSON']
  ];
  const results = [];
  for (const [attackId, path, expected] of probes) {
    const requestId = makeId(), checkedAt = now();
    let observed = 'not_run';
    try {
      const response = await fetcher(new URL(path, config.publicAppUrl), {
        method: 'GET', redirect: 'error', cache: 'no-store',
        headers: { 'X-Aleph-Request-Id': requestId, 'X-Aleph-Attack-Id': attackId },
        signal: AbortSignal.timeout(8000)
      });
      let body;
      if (path !== '/data.json') {
        try { body = await response.json(); } catch { /* Invalid JSON is not success. */ }
      }
      const responseValid = path === '/data.json' ? response.status === 404
        : path === '/api/notes' ? [401,403].includes(response.status)
          && response.headers.get('content-type')?.includes('application/json') === true
          && body && Object.keys(body).length === 1 && ['unauthorized','forbidden'].includes(body.error)
        : response.status === 200 && body?.schema === 'aleph.defense.deployment.v1'
          && body.step === config.step && /^[a-f0-9]{40}$/u.test(body.commit ?? '');
      // Describe only a real HTTP response, including failures, without asserting judge correlation.
      // The checker only permits an attackId/expected/observed triplet in the submission.
      observed = 'HTTP ' + response.status + ' · 응답 검증 ' +
        (responseValid ? '일치' : '불일치') +
        ' · 직접 HTTP 관측 · 서버 로그/심판 대조 미확인' +
        ' · 요청 ID ' + requestId + ' · 확인 시각 ' + checkedAt;
    } catch { /* No response means not_run, not an inferred denial or pass. */ }
    results.push({attackId, expected, observed});
  }
  return results;
}
