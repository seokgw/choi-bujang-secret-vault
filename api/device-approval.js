import { verifyRequest, safeOrigin, jsonHeaders } from '../src/vault-server.mjs';

// No enrollment backend is connected yet. The server must independently verify
// device proof and its owner on every protected request before returning true.
export async function isApprovedDevice(_request, _identity) {
  return false;
}
export function createDeviceApprovalHandler({
  verify = verifyRequest, origin = safeOrigin, approved = isApprovedDevice
} = {}) {
  return async function handler(request, response) {
    jsonHeaders(response);
    response.setHeader('Allow', 'GET, POST');
    if (!['GET', 'POST'].includes(request.method)) return response.status(405).json({ error: 'method_not_allowed' });
    try {
      const identity = await verify(request);
      if (!identity?.userId) return response.status(401).json({ error: 'unauthorized' });
      if (request.method === 'POST') {
        if (!origin(request, true)) return response.status(403).json({ error: 'origin_denied' });
        // A click is only a request. No client-chosen device identity is trusted.
        return response.status(202).json({ deviceApproval: 'pending', trusted: false, message: '서버 기기 증명 및 관리자 승인 연결 대기' });
      }
      const trusted = await approved(request, identity) === true;
      return response.status(200).json({ deviceApproval: trusted ? 'approved' : 'unverified', trusted });
    } catch {
      return response.status(503).json({ error: 'device_verification_unavailable' });
    }
  };
}
export default createDeviceApprovalHandler();
