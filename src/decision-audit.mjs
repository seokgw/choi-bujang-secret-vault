import { serverSettings } from './vault-server.mjs';
import { RULE_IDS } from './decider.mjs';

// Server-only audit: no request body, identities, tokens, memo content or device identifiers.
export function auditRecord(input, decision, { now = () => new Date().toISOString() } = {}) {
  if (!input || decision?.requestId !== input.requestId ||
      !/^[0-9a-f-]{36}$/iu.test(input.requestId) ||
      !['allow','deny','step_up'].includes(decision.decision) ||
      !Array.isArray(decision.ruleIds) ||
      decision.ruleIds.some(id => !RULE_IDS.includes(id))) throw Error('invalid_decision_audit');
  return {request_id:input.requestId.toLowerCase(),evaluated_at:now(),
    decision:decision.decision,reason_code:decision.reasonCode,
    rule_ids:decision.ruleIds,source:'decision_fixture_api'};
}
export async function persistDecisionAudit(input, decision, {
  fetcher=fetch, settings=serverSettings, now=()=>new Date().toISOString()
}={}) {
  // Disabled until the database migration and Vercel env setting are configured.
  if (process.env.DECISION_AUDIT_ENABLED !== 'true') return { saved:false, state:'not_configured' };
  const record=auditRecord(input,decision,{now});
  const {key,url}=settings();
  const endpoint=new URL('/rest/v1/decision_audit',url);
  const response=await fetcher(endpoint,{method:'POST',redirect:'error',
    headers:{apikey:key,'Accept-Profile':'vault_api','Content-Profile':'vault_api',
      'Content-Type':'application/json',Prefer:'return=minimal'},
    body:JSON.stringify(record),signal:AbortSignal.timeout(8000)});
  if (!response.ok) throw Error('decision_audit_write_failed');
  return {saved:true,state:'persisted'};
}
export async function readDecisionAudit({fetcher=fetch,settings=serverSettings}={}) {
  if (process.env.DECISION_AUDIT_ENABLED!=='true') return null;
  const {key,url}=settings();
  const endpoint=new URL('/rest/v1/decision_audit',url);
  endpoint.searchParams.set('select','request_id,evaluated_at,decision,reason_code,rule_ids,source');
  endpoint.searchParams.set('order','evaluated_at.desc');
  endpoint.searchParams.set('limit','100');
  const response=await fetcher(endpoint,{method:'GET',redirect:'error',
    headers:{apikey:key,'Accept-Profile':'vault_api'},
    signal:AbortSignal.timeout(8000)});
  if(!response.ok)throw Error('decision_audit_read_failed');
  const rows=await response.json();
  if(!Array.isArray(rows)||rows.length>100)throw Error('invalid_decision_audit_rows');
  return rows.filter(r=>r && typeof r.request_id==='string' && RULE_IDS.length &&
    Array.isArray(r.rule_ids) && r.rule_ids.every(id=>RULE_IDS.includes(id))
    && ['allow','deny','step_up'].includes(r.decision) &&
    typeof r.evaluated_at==='string')
    .map(r=>({requestId:r.request_id,checkedAt:r.evaluated_at,
      decision:r.decision,reasonCode:r.reason_code,ruleIds:r.rule_ids}));
}
