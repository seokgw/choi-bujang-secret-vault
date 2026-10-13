// Stage 12: offline comparison only. Never upload raw Vercel logs to GitHub.
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export function compareEvidence(jsonl, summary) {
  const events = [];
  for (const line of jsonl.split(/\r?\n/u)) {
    if (!line.trim().startsWith('{')) continue; // tolerate pasted CLI prompts
    let x;
    try { x = JSON.parse(line); } catch { continue; }
    if (x?.environment !== 'production' || !['GET','POST','PUT','DELETE','PATCH'].includes(x.requestMethod)
        || typeof x.requestPath !== 'string' || !Number.isInteger(x.responseStatusCode)
        || typeof x.id !== 'string' || !Number.isSafeInteger(x.timestamp)) continue;
    events.push({ id: x.id, path: x.requestPath, method: x.requestMethod,
      status: x.responseStatusCode, at: new Date(x.timestamp).toISOString() });
  }
  const records = Array.isArray(summary?.http?.records) ? summary.http.records : [];
  const rows = records.map(r => {
    const path = { static_note_removal:'/data.json',
      anonymous_note_rejection:'/api/notes',
      deployment_identity:'/aleph.json' }[r.attackId];
    if (!path) return { attackId: String(r.attackId), status: 'not_run' };
    // Only match a request ID if it is exactly a Vercel-issued log ID.
    // Client-side UUIDs / approximate timestamps are NOT proof.
    const e = events.find(x => x.id === r.requestId && x.path === path && x.method === 'GET'
      && x.status === r.httpStatus);
    return { attackId: r.attackId, expectedPath: path,
      apiStatus: Number.isInteger(r.httpStatus) ? r.httpStatus : null,
      correlation: e ? 'vercel_id_matched' : 'not_run',
      vercelRequestId: e?.id ?? null, checkedAt: e?.at ?? null,
      // ALEPH judge verification is a separate system.
      judgeVerified: false };
  });
  return { schema: 'aleph.log-comparison.v1', source: 'vercel_cli_export',
    recordsRead: events.length, matched: rows.filter(r=>r.correlation==='vercel_id_matched').length,
    judgeVerified: null, records: rows };
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [logPath, summaryPath, outputPath] = process.argv.slice(2);
  if (!logPath || !summaryPath || !outputPath) {
    console.error('사용법: node scripts/compare-vercel-evidence.mjs <vercel.jsonl> <operations-response.json> <redacted-result.json>');
    process.exitCode = 1;
  } else {
    const report = compareEvidence(readFileSync(logPath,'utf8'),JSON.parse(readFileSync(summaryPath,'utf8')));
    writeFileSync(outputPath,JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
    console.log('가린 기록 비교 완료: 로그 '+report.recordsRead+'건, 요청 ID 완전 일치 '+report.matched+'건. ALEPH 판정은 별도.');
  }
}
