import { test } from 'node:test';
import assert from 'node:assert/strict';
import { auditRecord,persistDecisionAudit,readDecisionAudit } from '../src/decision-audit.mjs';
const input={requestId:'11111111-1111-4111-8111-111111111111',deviceId:'PRIVATE-DEVICE',subjectId:'PRIVATE-USER',path:'/notes/123'};
const decision={requestId:input.requestId,decision:'deny',reasonCode:'device_not_registered',ruleIds:['device_registered']};
test('audit retains only redacted result metadata',()=>{
 const row=auditRecord(input,decision,{now:()=> '2026-10-13T08:00:00Z'});
 assert.deepEqual(Object.keys(row).sort(),['decision','evaluated_at','reason_code','request_id','rule_ids','source'].sort());
 assert.equal(JSON.stringify(row).includes('PRIVATE'),false);
});
test('configured audit writes to private Supabase REST schema',async()=>{
 const original=process.env.DECISION_AUDIT_ENABLED;
 process.env.DECISION_AUDIT_ENABLED='true';
 try{
  let request;
  const result=await persistDecisionAudit(input,decision,{
   settings:()=>({key:'server-only',url:new URL('https://example.supabase.co/')}),
   fetcher:async(url,options)=>{request={url:String(url),options};return {ok:true};}
  });
  assert.equal(result.saved,true);
  assert.equal(request.url,'https://example.supabase.co/rest/v1/decision_audit');
  assert.equal(request.options.headers['Content-Profile'],'vault_api');
  assert.equal(JSON.parse(request.options.body).request_id,input.requestId);
  assert.equal(request.options.body.includes('PRIVATE'),false);
 }finally{if(original===undefined)delete process.env.DECISION_AUDIT_ENABLED;else process.env.DECISION_AUDIT_ENABLED=original;}
});
test('failed audit insertion throws rather than returning a success record',async()=>{
 const original=process.env.DECISION_AUDIT_ENABLED;
 process.env.DECISION_AUDIT_ENABLED='true';
 try{
  await assert.rejects(()=>persistDecisionAudit(input,decision,{
   settings:()=>({key:'server-only',url:new URL('https://example.supabase.co/')}),
   fetcher:async()=>({ok:false,status:403})
  }),/decision_audit_write_failed/);
 }finally{if(original===undefined)delete process.env.DECISION_AUDIT_ENABLED;else process.env.DECISION_AUDIT_ENABLED=original;}
});
