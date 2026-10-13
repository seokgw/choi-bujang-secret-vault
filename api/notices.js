import config from '../aleph.config.json' with { type: 'json' };
import { serverSettings, verifyRequest, safeOrigin, bodyObject, jsonHeaders } from '../src/vault-server.mjs';
import { activeVaultDeny } from '../src/vault-xdr.mjs';
import { rejectApi } from '../src/api-denial.mjs';
import { resourceIdForPath } from '../src/resources.mjs';

export function createNoticesHandler({ verify = verifyRequest, settings = serverSettings,
  fetcher = (...args) => fetch(...args), deny = activeVaultDeny, detailRoute = false } = {}) {
  return async function handler(request, response) {
    jsonHeaders(response);
    const id = request.query?.id;
    const validId = typeof id === 'string' && /^[1-9][0-9]{0,9}$/u.test(id)
      && Number(id) <= 2147483647;
    response.setHeader('X-Aleph-Resource-Id', resourceIdForPath(validId ? `/api/notices/${id}` : '/api/notices'));
    try {
      const identity = await verify(request);
      if (!identity || !['student', 'judge'].includes(identity.kind)
          || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(identity.userId)) {
        return rejectApi(response, 401, 'unauthorized', 'login_required');
      }
      if (await deny(identity)) return rejectApi(response, 403, 'forbidden', 'xdr_denied');
      const methods = detailRoute ? ['GET', 'PUT', 'PATCH'] : ['GET'];
      if (!methods.includes(request.method)) {
        response.setHeader('Allow', methods.join(', '));
        return rejectApi(response, 405, 'method_not_allowed', 'method_not_allowed');
      }
      // Query values may select a record only, never an action or role.
      if (Object.keys(request.query ?? {}).some(key => key !== 'id') || (detailRoute && !validId)
          || (id !== undefined && !validId)) {
        return rejectApi(response, 400, 'invalid_request', 'invalid_resource');
      }
      if (request.method !== 'GET' && !safeOrigin(request)) {
        return rejectApi(response, 403, 'forbidden', 'origin_denied');
      }
      const { key, url } = settings();
      const headers = { apikey: key, 'Accept-Profile': 'vault_api', 'Content-Profile': 'vault_api',
        'Content-Type': 'application/json' };
      if (request.method !== 'GET') {
        const body = bodyObject(request);
        if (!body || typeof body.title !== 'string' || !body.title.trim() || body.title.length > 200
            || typeof body.content !== 'string' || !body.content.trim() || body.content.length > 10000) {
          return rejectApi(response, 400, 'invalid_request', 'invalid_body');
        }
        const upstream = await fetcher(new URL('/rest/v1/rpc/update_training_notice', url), {
          method: 'POST', headers, redirect: 'error', signal: AbortSignal.timeout(10000),
          body: JSON.stringify({ p_app_origin: new URL(config.publicAppUrl).origin,
            p_issuer: identity.kind === 'judge' ? config.judgeIssuer : config.identityProvider.issuer,
            p_user_id: identity.userId, p_id: Number(id), p_title: body.title.trim(), p_content: body.content.trim() }),
        });
        if (!upstream.ok) throw new Error();
        const result = await upstream.json();
        if (result?.error === 'instructor_required') return rejectApi(response, 403, 'forbidden', 'instructor_required');
        if (result?.error === 'not_found') return rejectApi(response, 404, 'not_found', 'resource_unavailable');
        const note = result?.notice;
        if (note?.id !== Number(id) || typeof note.title !== 'string' || typeof note.content !== 'string') throw new Error();
        return response.status(200).json({ id: note.id, title: note.title, content: note.content });
      }
      const endpoint = new URL('/rest/v1/training_notices', url);
      endpoint.searchParams.set('select', 'id,title,content');
      endpoint.searchParams.set('order', 'id.asc');
      if (validId) endpoint.searchParams.set('id', `eq.${id}`);
      const upstream = await fetcher(endpoint, { headers, redirect: 'error', signal: AbortSignal.timeout(10000) });
      if (!upstream.ok) throw new Error();
      const rows = await upstream.json();
      if (!Array.isArray(rows) || rows.some(row => !Number.isInteger(row.id)
          || typeof row.title !== 'string' || typeof row.content !== 'string')) throw new Error();
      if (detailRoute) {
        if (!rows.length) return rejectApi(response, 404, 'not_found', 'resource_unavailable');
        if (rows.length !== 1 || rows[0].id !== Number(id)) throw new Error();
        return response.status(200).json({ id: rows[0].id, title: rows[0].title, content: rows[0].content });
      }
      return response.status(200).json({ notices: rows.map(({ id, title, content }) => ({ id, title, content })) });
    } catch {
      return rejectApi(response, 503, 'service_unavailable', 'permission_check_unavailable');
    }
  };
}
export default createNoticesHandler();
