import { createDeviceApprovalHandler } from './device-approval.js';
// Compatibility endpoint: same server-confirmed state as the approval API.
export const createDeviceStatusHandler = ({ verify, approved } = {}) =>
  createDeviceApprovalHandler({ verify, approved });
export default createDeviceStatusHandler();
