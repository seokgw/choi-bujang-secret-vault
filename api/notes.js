import { serverSettings, verifyRequest, safeOrigin, bodyObject,
  jsonHeaders } from '../src/vault-server.mjs';
import { activeVaultDeny } from '../src/vault-xdr.mjs';
import { decide } from '../src/decider.mjs';

const decisionKeys = ['schema', 'requestId', 'classId', 'projectId', 'subjectId', 'deviceId',
  'service', 'method', 'path', 'route', 'queryLength', 'querySha256', 'at', 'policyRevision',
  'deviceRegistered', 'stepUp', 'recentEvents', 'signals'].sort().join(',');

function decisionInput(body) {
  const keys = value => value && typeof value === 'object' && !Array.isArray(value)
    ? Object.keys(value).sort().join(',') : '';
  return keys(body) === decisionKeys && body.schema === 'aleph.decision.v1'
    && ['requestId', 'classId', 'projectId', 'subjectId', 'service', 'method', 'path', 'route']
      .every(key => typeof body[key] === 'string' && body[key].length > 0 && body[key].length <= 512)
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(body.requestId)
    && /^[0-9a-f]{16}$/u.test(body.deviceId) && /^[0-9a-f]{64}$/u.test(body.querySha256)
    && Number.isSafeInteger(body.queryLength) && body.queryLength >= 0
    && Number.isSafeInteger(body.policyRevision) && body.policyRevision >= 0
    && typeof body.at === 'string' && Number.isFinite(Date.parse(body.at))
    && Math.abs(Date.now() - Date.parse(body.at)) <= 5000
    && typeof body.deviceRegistered === 'boolean'
    && keys(body.stepUp) === 'authAgeSeconds,verified'
    && (body.stepUp.verified === false && body.stepUp.authAgeSeconds === null
      || body.stepUp.verified === true && Number.isFinite(body.stepUp.authAgeSeconds)
        && body.stepUp.authAgeSeconds >= 0 && body.stepUp.authAgeSeconds <= 900)
    && Array.isArray(body.recentEvents) && body.recentEvents.length <= 12
    && body.recentEvents.every(event => keys(event) === 'ageSeconds,count,kind'
      && typeof event.kind === 'string' && Number.isFinite(event.ageSeconds) && event.ageSeconds >= 0
      && Number.isSafeInteger(event.count) && event.count >= 0)
    && keys(body.signals) === 'hour,network,region,source'
    && ['source', 'region', 'network'].every(key => typeof body.signals[key] === 'string')
    && Number.isInteger(body.signals.hour) && body.signals.hour >= 0 && body.signals.hour <= 23;
}

// Every query binds ownership to the identity verified by verify-login.mjs.
export function createNotesHandler({ verify = verifyRequest, settings = serverSettings,
  fetcher = (...args) => fetch(...args), detailRoute = false, deny = activeVaultDeny } = {}) {
  return async function handler(request, response) {
    jsonHeaders(response);
    try {
      if (!detailRoute && request.method === 'POST') {
        const body = bodyObject(request);
        if (body?.schema === 'aleph.decision.v1') {
          if (!decisionInput(body)) return response.status(400).json({ error: 'invalid_request' });
          // Compute only: these caller-supplied fields never authorize note CRUD.
          return response.status(200).json(await decide(body));
        }
      }
      const identity = await verify(request);
      if (!identity) return response.status(401).json({ error: 'unauthorized' });
      if (await deny(identity)) return response.status(403).json({ error: 'forbidden' });
      const methods = detailRoute ? ['GET', 'PUT', 'PATCH', 'DELETE'] : ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
      if (!methods.includes(request.method)) {
        response.setHeader('Allow', methods.join(', '));
        return response.status(405).json({ error: 'method_not_allowed' });
      }
      if (request.method !== 'GET' && !safeOrigin(request)) {
        return response.status(403).json({ error: 'forbidden' });
      }
      const { key, url } = settings();
      const endpoint = new URL('/rest/v1/training_notes', url);
      endpoint.searchParams.set('select', 'id,title,content,owner_id');
      endpoint.searchParams.set('owner_id', `eq.${identity.userId}`);
      const headers = { apikey: key, 'Accept-Profile': 'vault_api',
        'Content-Profile': 'vault_api', 'Content-Type': 'application/json', Prefer: 'return=representation' };
      const init = { method: request.method === 'PUT' ? 'PATCH' : request.method,
        headers, redirect: 'error', signal: AbortSignal.timeout(10000) };
      if (request.method === 'GET') endpoint.searchParams.set('order', 'id.asc');
      const hasId = detailRoute || ['PUT', 'PATCH', 'DELETE'].includes(request.method)
        || (request.method === 'GET' && request.query?.id !== undefined);
      if (hasId) {
        const id = request.query?.id;
        if (typeof id !== 'string' || !/^[1-9][0-9]{0,9}$/u.test(id) || Number(id) > 2147483647) {
          return response.status(400).json({ error: 'invalid_request' });
        }
        endpoint.searchParams.set('id', `eq.${id}`);
      }
      if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
        const body = bodyObject(request);
        if (!body || typeof body.title !== 'string' || !body.title.trim() || body.title.length > 200
            || typeof body.content !== 'string' || !body.content.trim() || body.content.length > 10000) {
          return response.status(400).json({ error: 'invalid_request' });
        }
        // Never copy browser-provided ownership, userId, role or database id.
        const note = { title: body.title.trim(), content: body.content.trim() };
        if (request.method === 'POST') note.owner_id = identity.userId;
        init.body = JSON.stringify(note);
      }
      const upstream = await fetcher(endpoint, init);
      if (!upstream.ok) throw new Error();
      const rows = await upstream.json();
      if (!Array.isArray(rows) || rows.some(row => !Number.isInteger(row.id)
          || typeof row.title !== 'string' || typeof row.content !== 'string'
          || row.owner_id !== identity.userId)) throw new Error();
      // Missing and foreign IDs have the same response; no ownership disclosure.
      if (hasId && rows.length === 0) {
        return response.status(404).json({ error: 'not_found' });
      }
      if (request.method === 'DELETE') return response.status(200).json({ deleted: true });
      const notes = rows.map(({ id, title, content }) => ({ id, title, content }));
      if (detailRoute && request.method === 'GET') {
        if (notes.length !== 1) throw new Error();
        return response.status(200).json(notes[0]);
      }
      return response.status(request.method === 'POST' ? 201 : 200).json({ notes });
    } catch {
      return response.status(503).json({ error: 'service_unavailable' });
    }
  };
}
export default createNotesHandler();
