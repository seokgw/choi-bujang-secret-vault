import { verifyRequest, jsonHeaders } from '../src/vault-server.mjs';
import { RULE_IDS } from '../src/decider.mjs';
import { isApprovedDevice } from './device-approval.js';

// Redacted server evidence only; no note bodies, user IDs, credentials or raw events.
export function createOperationsHandler({ verify = verifyRequest, deviceCheck = isApprovedDevice } = {}) {
  return async function handler(req, res) {
    jsonHeaders(res);
    res.setHeader('Allow', 'GET');
    if (req.method !== 'GET') return res.status(405).json({ error: 'method_not_allowed' });
    try {
      const identity = await verify(req);
      if (!identity?.userId) return res.status(401).json({ error: 'unauthorized' });
      let deviceStatus = 'not_run';
      let approved = false;
      try {
        approved = await deviceCheck(req, identity) === true;
        deviceStatus = 'api_verified';
      } catch { /* No evidence is not approval. */ }
      return res.status(200).json({
        schema: 'aleph.operations.summary.v1',
        policy: { status: 'code_inventory', count: RULE_IDS.length, rules: [...RULE_IDS] },
        detection: { status: 'not_run', count: null },
        revocation: { status: 'not_run', count: null },
        recovery: { status: 'not_run', version: null, count: null },
        device: { status: deviceStatus, approved },
        assault: { status: 'not_run', total: 41, defended: null }
      });
    } catch { return res.status(503).json({ error: 'evidence_unavailable' }); }
  };
}
export default createOperationsHandler();
