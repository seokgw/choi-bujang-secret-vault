// Direct production API probes with synthetic fixture only; never claim judge validation.
import { randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import config from '../aleph.config.json' with { type: 'json' };
import { fixtureRequests } from './fixture-7.mjs';

const cases=[
  ['device_registered','미등록 기기 차단','deny',b=>({...b,deviceRegistered:false})],
  ['step_up_required','위험 요청 추가 인증','step_up',(_,s)=>s],
  ['zone_known_resource','금지 경로 차단','deny',b=>({...b,path:'/notes/export',route:'GET /notes/:id'})],
  ['zone_memo_own','정상 단건 메모 판정','allow',b=>({...b,path:'/notes/fixture-item',route:'GET /notes/:id'})],
  ['zone_announcement_write','공지 구역 접근 차단','deny',b=>({...b,path:'/notices/fixture-item',route:'GET /notices/:id'})]
];
export async function checkProduction({fetcher=fetch,clock=()=>new Date().toISOString()}={}){
  const base=new URL(config.publicAppUrl);
  const url=new URL('/api/decider',base);
  if(base.protocol!=='https:')throw Error('HTTPS required');
  const rows=[];
  for(const [ruleId,displayName,expectedDecision,change] of cases){
    const {normal,suspicious}=fixtureRequests();
    const body=change({...normal},suspicious);
    body.requestId=randomUUID();
    body.at=clock();
    const checkedAt=clock();
    let httpStatus=null,actualDecision=null,actualReasonCode=null,ruleIds=[],error=null,responseId=null;
    try{
      const res=await fetcher(url,{method:'POST',cache:'no-store',redirect:'error',
        headers:{'Content-Type':'application/json','Accept':'application/json'},
        body:JSON.stringify(body),signal:AbortSignal.timeout(10000)});
      httpStatus=res.status;
      const data=await res.json();
      if(data?.schema==='aleph.decision.v1'&&data.requestId===body.requestId
        &&['allow','deny','step_up'].includes(data.decision)
        &&Array.isArray(data.ruleIds)&&data.ruleIds.every(x=>typeof x==='string')){
        actualDecision=data.decision;
        actualReasonCode=typeof data.reasonCode==='string'?data.reasonCode:null;
        ruleIds=data.ruleIds.filter(id=>cases.some(c=>c[0]===id));
        responseId=data.requestId;
      }else error='invalid_or_uncorrelated_api_response';
    }catch{error='request_or_response_failed';}
    const responseObserved=httpStatus!==null;
    const decisionConfirmed=httpStatus===200&&responseId===body.requestId
      &&ruleIds.includes(ruleId)&&actualDecision===expectedDecision;
    rows.push({ruleId,displayName,method:'POST',path:'/api/decider',
      expectedDecision,actualDecision,actualReasonCode,ruleIds,
      httpStatus,requestId:body.requestId,responseId,checkedAt,
      status:decisionConfirmed?'api_response_matched':responseObserved?'api_response_unverified':'not_run',
      matched:decisionConfirmed,judgeVerified:false,error});
  }
  return {schema:'aleph.stage12.decider-api-evidence.v1',source:'production_direct_http',
    notice:'Synthetic fixture API results are not authorization proofs or ALEPH judge records.',
    observed:rows.filter(r=>r.httpStatus!==null).length,
    apiResponsesMatched:rows.filter(r=>r.matched).length,
    judgeVerified:null,records:rows};
}
if(process.argv[1]&&import.meta.url===new URL('../scripts/check-decider-live.mjs',import.meta.url).href){
 try{
  const result=await checkProduction();
  const path='decider-live-evidence.local.json';
  writeFileSync(path,JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600});
  console.log('운영 판정 API 응답 '+result.observed+'/5, 예상 판정과 응답 ID 확인 '+
    result.apiResponsesMatched+'/5. 결과: '+path+' (ALEPH 심판 결과 아님)');
 }catch(e){console.error('운영 판정 API 확인 실패: '+e.message);process.exitCode=1;}
}
