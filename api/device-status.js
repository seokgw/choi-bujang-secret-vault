import { verifyRequest, jsonHeaders } from '../src/vault-server.mjs';
// Informational status only. Do not infer trust from a PWA installation or client flags.
export function createDeviceStatusHandler({ verify = verifyRequest } = {}) {
  return async (req, res) => {
    jsonHeaders(res);
    res.setHeader('Allow', 'GET');
    if (req.method !== 'GET') return res.status(405).json({ error: 'method_not_allowed' });
    try {
      const identity = await verify(req);
      if (!identity) return res.status(401).json({ error: 'unauthorized' });
      // No server-verified device enrollment provider exists yet: fail closed.
      return res.status(200).json({ deviceApproval: 'unverified', trusted: false });
    } catch { return res.status(503).json({ error: 'service_unavailable' }); }
  };
}
export default createDeviceStatusHandler();
