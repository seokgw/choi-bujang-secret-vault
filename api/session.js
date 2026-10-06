import { COOKIE, serverSettings, sessionToken, verifyRequest, safeOrigin,
  bodyObject, jsonHeaders } from '../src/vault-server.mjs';

export function createSessionHandler({ settings = serverSettings, verify = verifyRequest,
  fetcher = (...args) => fetch(...args) } = {}) {
  return async function handler(request, response) {
    jsonHeaders(response);
    if (!['GET', 'POST', 'DELETE'].includes(request.method)) {
      response.setHeader('Allow', 'GET, POST, DELETE');
      return response.status(405).json({ error: 'method_not_allowed' });
    }
    if (request.method !== 'GET' && !safeOrigin(request, true)) {
      return response.status(403).json({ error: 'forbidden' });
    }
    try {
      if (request.method === 'GET') {
        if (!await verify(request)) return response.status(401).json({ error: 'unauthorized' });
        return response.status(200).json({ authenticated: true });
      }
      if (request.method === 'DELETE') {
        const token = sessionToken(request);
        response.setHeader('Set-Cookie', `${COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`);
        if (token) {
          try {
            const { key, url } = settings();
            await fetcher(new URL('/auth/v1/logout?scope=local', url), {
              method: 'POST', headers: { apikey: key, Authorization: `Bearer ${token}` },
              redirect: 'error', signal: AbortSignal.timeout(10000),
            });
          } catch { /* Always end this browser's local session. */ }
        }
        return response.status(200).json({ authenticated: false });
      }
      const body = bodyObject(request);
      if (!body || typeof body.email !== 'string' || body.email.length > 320
          || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(body.email)
          || typeof body.password !== 'string' || !body.password || body.password.length > 1024) {
        return response.status(400).json({ error: 'invalid_request' });
      }
      const { key, url } = settings();
      const upstream = await fetcher(new URL('/auth/v1/token?grant_type=password', url), {
        method: 'POST', headers: { apikey: key, 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: body.email, password: body.password }),
        redirect: 'error', signal: AbortSignal.timeout(10000),
      });
      if (!upstream.ok) return response.status(401).json({ error: 'unauthorized' });
      const data = await upstream.json();
      if (typeof data.access_token !== 'string'
          || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(data.access_token)
          || !await verify({ headers: { authorization: `Bearer ${data.access_token}` } })) {
        return response.status(401).json({ error: 'unauthorized' });
      }
      const seconds = Number.isInteger(data.expires_in) ? Math.min(3600, Math.max(1, data.expires_in)) : 3600;
      response.setHeader('Set-Cookie', `${COOKIE}=${data.access_token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${seconds}`);
      return response.status(200).json({ authenticated: true });
    } catch {
      return response.status(503).json({ error: 'service_unavailable' });
    }
  };
}
export default createSessionHandler();
