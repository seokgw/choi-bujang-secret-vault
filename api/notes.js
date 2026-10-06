// Stage 2: deliberately public. Authentication/authorization comes later.
export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  try {
    const key = process.env.SUPABASE_SECRET_KEY;
    const url = new URL(process.env.SUPABASE_URL);
    if (!key || url.protocol !== 'https:' || url.username || url.password
        || url.search || url.hash || url.pathname !== '/') throw new Error();
    const endpoint = new URL('/rest/v1/training_notes', url);
    endpoint.searchParams.set('select', 'title,content');
    endpoint.searchParams.set('order', 'id.asc');
    const upstream = await fetch(endpoint, {
      headers: { apikey: key, 'Accept-Profile': 'vault_api' }, redirect: 'error',
      signal: AbortSignal.timeout(10000),
    });
    if (!upstream.ok) throw new Error();
    const rows = await upstream.json();
    if (!Array.isArray(rows) || rows.some(row => typeof row.title !== 'string'
        || typeof row.content !== 'string')) throw new Error();
    return response.status(200).json({ notes: rows.map(({ title, content }) => ({ title, content })) });
  } catch {
    // Never forward upstream bodies, exceptions, environment values or stacks.
    return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
  }
}
