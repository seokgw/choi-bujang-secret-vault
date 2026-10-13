import { serverSettings, verifyRequest, safeOrigin, bodyObject,
  jsonHeaders } from '../src/vault-server.mjs';
import { activeVaultDeny } from '../src/vault-xdr.mjs';

// Every query binds ownership to the identity verified by verify-login.mjs.
export function createNotesHandler({ verify = verifyRequest, settings = serverSettings,
  fetcher = (...args) => fetch(...args), detailRoute = false, deny = activeVaultDeny } = {}) {
  return async function handler(request, response) {
    jsonHeaders(response);
    try {
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
