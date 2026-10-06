import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from './verify-login.mjs';

export const COOKIE = '__Host-vault-session';
let verifier;
export function serverSettings() {
  const key = process.env.SUPABASE_SECRET_KEY;
  const url = new URL(process.env.SUPABASE_URL);
  if (!key || url.origin !== new URL(config.identityProvider.issuer).origin
      || url.protocol !== 'https:' || url.username || url.password
      || url.search || url.hash || url.pathname !== '/') throw new Error('invalid_server_configuration');
  return { key, url };
}
export function sessionToken(request) {
  const raw = request.headers?.cookie;
  if (typeof raw !== 'string' || raw.length > 16384) return null;
  const entries = raw.split(';').map(part => part.trim());
  const matches = entries.filter(part => part.startsWith(`${COOKIE}=`));
  if (matches.length !== 1) return null;
  const token = matches[0].slice(COOKIE.length + 1);
  return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(token) ? token : null;
}
export async function verifyRequest(request) {
  const header = request.headers?.authorization;
  const token = sessionToken(request);
  const authorization = header ?? (token ? `Bearer ${token}` : null);
  if (typeof authorization !== 'string' || authorization.length > 8192
      || !/^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(authorization)) return null;
  if (!verifier) verifier = createLoginVerifier({ config, supabaseSecretKey: serverSettings().key });
  return verifier(authorization);
}
export function safeOrigin(request, requireOrigin = false) {
  const origin = request.headers?.origin;
  if (origin) return origin === new URL(config.publicAppUrl).origin;
  return !requireOrigin && typeof request.headers?.authorization === 'string';
}
export function jsonHeaders(response) {
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
}
export function bodyObject(request) {
  let body = request.body;
  if (typeof body === 'string') {
    if (Buffer.byteLength(body) > 65536) return null;
    try { body = JSON.parse(body); } catch { return null; }
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)
      || Buffer.byteLength(JSON.stringify(body)) > 65536) return null;
  return body;
}
