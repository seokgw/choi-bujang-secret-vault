import { createDeviceApprovalHandler } from './device-approval.js';
export function createDeviceStatusHandler({ verify, approved } = {}) {
  const handler = createDeviceApprovalHandler({ verify, approved });
  return (request, response) => {
    if (request.method !== 'GET') {
      response.setHeader('Allow', 'GET');
      return response.status(405).json({ error: 'method_not_allowed' });
    }
    return handler(request, response);
  };
}
export default createDeviceStatusHandler();
