import { appendFile } from 'node:fs/promises';
import { decide as baselineDecide } from '../../src/decider.mjs';

const RULE = 'xdr.privilege.deny';
const VALID = new Set(['unexpected-admin-group-membership','unexpected-administrator-command','off-hours-elevated-access']);
const KEYS = ['classId','projectId','subjectId','deviceId'];
const TTL = 900000;
const idOK = x => typeof x === 'string' && /^[\w-]{1,80}$/.test(x);
const high = x => Number.isFinite(x) && x >= 0.85 && x <= 1;

export function createDenyRules(decisions, bindings = [], now = Date.now()) {
  if (!Array.isArray(decisions) || !Array.isArray(bindings)) throw Error('invalid_input');
  const rules = [];
  for (const d of decisions) {
    if (d?.action !== 'block' || !high(d.confidence) || !VALID.has(d.reason) || !idOK(d.alertId)) continue;
    const verified = bindings.filter(b => b?.trusted === true && b.alertId === d.alertId
      && KEYS.every(k => typeof b[k] === 'string' && b[k].length > 0));
    if (verified.length !== 1) continue;
    const b = verified[0];
    rules.push({ruleId:RULE,alertId:d.alertId,pattern:d.reason,action:'block',
      confidence:d.confidence,...Object.fromEntries(KEYS.map(k=>[k,b[k]])),
      issuedAt:new Date(now).toISOString(),expiresAt:new Date(now+TTL).toISOString()});
  }
  return {schema:'aleph.xdr.bound-deny.v1',rules};
}

export function matchDeny(request, document, now = Date.now()) {
  if (request?.schema !== 'aleph.decision.v1' || document?.schema !== 'aleph.xdr.bound-deny.v1'
    || !Array.isArray(document.rules)) return null;
  return document.rules.find(r => {
    const start = Date.parse(r.issuedAt), end = Date.parse(r.expiresAt);
    return r.ruleId === RULE && r.action === 'block' && VALID.has(r.pattern)
      && high(r.confidence) && idOK(r.alertId) && end-start === TTL
      && start <= now && now < end
      && KEYS.every(k => typeof request[k] === 'string' && request[k] === r[k]);
  }) ?? null;
}

export async function decideWithDenyRules(request, {document,now=Date.now()} = {}) {
  if (!matchDeny(request,document,now)) return baselineDecide(request);
  return {schema:'aleph.decision.v1',requestId:request.requestId,
    decision:'deny',reasonCode:'starter_not_ready',ruleIds:[RULE]};
}

export async function appendAlerts(decisions, path = new URL('../alerts.log',import.meta.url)) {
  if (!Array.isArray(decisions)) throw Error('invalid_decisions');
  let total = 0;
  for (const d of decisions) {
    if (!['block','alert'].includes(d?.action) || !idOK(d.alertId)
      || !Number.isFinite(d.confidence) || d.confidence < 0 || d.confidence > 1) continue;
    const entry = {moduleKey:'privilege',alertId:d.alertId,action:d.action,
      confidence:d.confidence,reason:VALID.has(d.reason)?d.reason:'unspecified',
      runAt:new Date().toISOString()};
    await appendFile(path,JSON.stringify(entry)+'\n');
    total++;
  }
  return total;
}
