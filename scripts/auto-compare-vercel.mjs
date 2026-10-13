// Read-only local automation: public probes + Vercel CLI logs. No credentials stored.
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import config from '../aleph.config.json' with { type: 'json' };

const PROBES = [
  {attackId:'static_note_removal',displayName:'공개 메모 파일 제거 확인',path:'/data.json',expected:[404]},
  {attackId:'anonymous_note_rejection',displayName:'비로그인 메모 접근 차단',path:'/api/notes',expected:[401,403]},
  {attackId:'deployment_identity',displayName:'배포 식별 정보 확인',path:'/aleph.json',expected:[200]}
];
export function parseLogs(raw, host) {
  const rows=[];
  for (const line of raw.split(/\r?\n/u)) {
    if(!line.trim().startsWith('{'))continue;
    let x;try{x=JSON.parse(line)}catch{continue}
    if(x.environment!=='production'||x.domain!==host||typeof x.id!=='string'
      ||!Number.isSafeInteger(x.timestamp)||!Number.isInteger(x.responseStatusCode)
      ||typeof x.requestPath!=='string'||typeof x.requestMethod!=='string')continue;
    rows.push({id:x.id,at:new Date(x.timestamp).toISOString(),method:x.requestMethod,
      path:x.requestPath,status:x.responseStatusCode});
  }
  return rows;
}
export function reconcile(probes,logs) {
  const records=probes.map(p=>{
    const exact=logs.find(l=>l.id===p.vercelId && l.path===p.path
      && l.method==='GET' && l.status===p.httpStatus);
    // A URL/time/status similarity is not enough to establish request identity.
    return {attackId:p.attackId,displayName:p.displayName??p.attackId,path:p.path,expected:p.expected,
      httpStatus:p.httpStatus,observedAt:p.observedAt,
      evidence:exact?'vercel_id_matched':p.httpStatus===null?'not_run':'http_unverified',
      requestId:exact?.id??null,serverAt:exact?.at??null,
      judgeVerified:false};
  });
  return {schema:'aleph.stage12.auto-compare.v1',source:'vercel_cli',
    serverLogsRead:logs.length,verifiedMatches:records.filter(r=>r.evidence==='vercel_id_matched').length,
    // Presence of unrelated logged requests is not evidence of these probes.
    matchedJudgeAttacks:null,records,
    serverObservations:logs.filter(l=>['/api/notes','/api/operations','/api/session'].includes(l.path))
      .map(({id,at,method,path,status})=>({id,at,method,path,status}))};
}
export async function runAuto({fetcher=fetch,readLogs,now=()=>new Date().toISOString(),
  output='stage12-auto-compare.local.json'}={}) {
  const base=new URL(config.publicAppUrl);
  const probes=[];
  for(const p of PROBES){
    const observedAt=now();
    let httpStatus=null,vercelId=null;
    try{
      const response=await fetcher(new URL(p.path,base),{method:'GET',cache:'no-store',
        redirect:'error',headers:{'X-Aleph-Attack-Id':p.attackId,'X-Aleph-Request-Id':randomUUID()},
        signal:AbortSignal.timeout(8000)});
      httpStatus=response.status;
      // Vercel may return a routing ID, not the logs' id. Never assume equality.
      const header=response.headers.get('x-vercel-id');
      if(header&&/^[a-zA-Z0-9:._-]{1,128}$/u.test(header))vercelId=header;
    }catch{}
    probes.push({...p,httpStatus,vercelId,observedAt});
  }
  const raw=readLogs();
  const logs=parseLogs(raw,base.hostname);
  const report=reconcile(probes,logs);
  writeFileSync(output,JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
  return report;
}
function cliLogs(){
  const args=['vercel@latest','logs','--environment','production','--since','30m','--limit','100','--json'];
  if(process.platform==='win32'){
    // cmd.exe is required for npm's npx.cmd shim; all arguments are constants.
    return execFileSync(process.env.ComSpec||'cmd.exe',['/d','/s','/c','npx.cmd '+args.join(' ')],
      {encoding:'utf8',timeout:90000,maxBuffer:2_000_000});
  }
  return execFileSync('npx',args,{encoding:'utf8',timeout:90000,maxBuffer:2_000_000});
}
if(process.argv[1]&&import.meta.url===new URL('../scripts/auto-compare-vercel.mjs',import.meta.url).href){
  try{
    const result=await runAuto({readLogs:cliLogs});
    console.log('Vercel 로그 '+result.serverLogsRead+'건, 동일 요청 ID 검증 '+result.verifiedMatches+
      '건; ALEPH 심판 검증 아님. stage12-auto-compare.local.json 확인');
  }catch(e){console.error('자동 대조 실패: '+e.message);process.exitCode=1}
}
