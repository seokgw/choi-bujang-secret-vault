import config from '../aleph.config.json' with { type: 'json' };
import { randomUUID } from 'node:crypto';
import { verifyRequest, jsonHeaders } from '../src/vault-server.mjs';
import { RULE_IDS } from '../src/decider.mjs';

const PROBES = Object.freeze([
  { attackId: 'static_note_removal', path: '/data.json', expected: [404] },
  { attackId: 'anonymous_note_rejection', path: '/api/notes', expected: [401, 403] },
  { attackId: 'deployment_identity', path: '/aleph.json', expected: [200] }
]);

export async function collectHttpEvidence({ fetcher = fetch, now = () => new Date().toISOString(),
  makeId = randomUUID } = {}) {
  const base = new URL(config.publicAppUrl);
  const evidence = [];
  for (const probe of PROBES) {
    const requestId = makeId();
    const checkedAt = now();
    try {
      const url = new URL(probe.path, base);
      const response = await fetcher(url, {
        method: 'GET', cache: 'no-store', redirect: 'error',
        headers: { 'X-Aleph-Request-Id': requestId, 'X-Aleph-Attack-Id': probe.attackId },
        signal: AbortSignal.timeout(8000)
      });
      // These are fresh HTTP observations, NOT persisted judge-log attestations.
      evidence.push({ attackId: probe.attackId, requestId, checkedAt,
        httpStatus: response.status, expected: [...probe.expected],
        matched: probe.expected.includes(response.status), source: 'direct_http',
        judgeCorrelated: false });
    } catch {
      evidence.push({ attackId: probe.attackId, requestId, checkedAt,
        httpStatus: null, expected: [...probe.expected], matched: null,
        source: 'not_run', judgeCorrelated: false });
    }
  }
  return evidence;
}

// No raw responses, memo bodies, credentials, identity identifiers or device keys.
export function createOperationsHandler({ verify = verifyRequest, evidenceSource = collectHttpEvidence } = {}) {
  return async (req, res) => {
    jsonHeaders(res);
    res.setHeader('Allow', 'GET');
    if (req.method !== 'GET') return res.status(405).json({ error: 'method_not_allowed' });
    try {
      const identity = await verify(req);
      if (!identity?.userId) return res.status(401).json({ error: 'unauthorized' });
      const observations = await evidenceSource();
      if (!Array.isArray(observations)) throw Error('invalid_evidence');
      const accepted = observations.filter(x => x && PROBES.some(p => p.attackId === x.attackId)
        && typeof x.requestId === 'string' && /^[a-zA-Z0-9-]{1,64}$/.test(x.requestId)
        && typeof x.checkedAt === 'string' && !Number.isNaN(Date.parse(x.checkedAt))
        && (x.httpStatus === null || (Number.isInteger(x.httpStatus) && x.httpStatus >= 100 && x.httpStatus <= 599))
        && x.source === (x.httpStatus === null ? 'not_run' : 'direct_http')
        && x.judgeCorrelated === false);
      const rows = PROBES.map(p => {
        const item = accepted.find(x => x.attackId === p.attackId);
        return item ? { attackId: p.attackId, requestId: item.requestId,
          checkedAt: item.checkedAt, httpStatus: item.httpStatus,
          expected: [...p.expected], matched: item.httpStatus === null ? null : p.expected.includes(item.httpStatus),
          status: item.httpStatus === null ? 'not_run' : 'api_observed',
          judgeCorrelated: false } :
          { attackId: p.attackId, requestId: null, checkedAt: null,
            httpStatus: null, expected: [...p.expected], matched: null,
            status: 'not_run', judgeCorrelated: false };
      });
      return res.status(200).json({
        schema: 'aleph.operations.summary.v1',
        policy: { status: 'code_inventory', count: null, rules: [...RULE_IDS], verifiedCount: null },
        http: { status: rows.some(x => x.status === 'api_observed') ? 'api_observed' : 'not_run',
          observed: rows.filter(x => x.status === 'api_observed').length, records: rows },
        detection: { status: 'not_run', count: null },
        revocation: { status: 'not_run', count: null },
        recovery: { status: 'not_run', version: null, count: null },
        device: { status: 'not_run', approved: false },
        assault: { status: 'not_run', total: 41, defended: null }
      });
    } catch { return res.status(503).json({ error: 'evidence_unavailable' }); }
  };
}
export default createOperationsHandler();
