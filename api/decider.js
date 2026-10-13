import { decide } from '../src/decider.mjs';
import { persistDecisionAudit } from '../src/decision-audit.mjs';
import { decisionInput } from '../src/decision-input.mjs';
import { bodyObject, jsonHeaders } from '../src/vault-server.mjs';

// Evaluation only: caller-supplied fixture fields never authorize note access.
export default async function handler(request, response) {
  jsonHeaders(response);
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return response.status(405).json({ error: 'method_not_allowed' });
  }
  try {
    const body = bodyObject(request);
    if (!decisionInput(body)) return response.status(400).json({ error: 'invalid_request' });
    const decision = await decide(body);
    const audit = await persistDecisionAudit(body, decision);
    response.setHeader('X-Decision-Audit', audit.state);
    return response.status(200).json(decision);
  } catch {
    return response.status(503).json({ error: 'service_unavailable' });
  }
}
