const decisionKeys = ['schema', 'requestId', 'classId', 'projectId', 'subjectId', 'deviceId',
  'service', 'method', 'path', 'route', 'queryLength', 'querySha256', 'at', 'policyRevision',
  'deviceRegistered', 'stepUp', 'recentEvents', 'signals'].sort().join(',');

export function decisionInput(body) {
  const keys = value => value && typeof value === 'object' && !Array.isArray(value)
    ? Object.keys(value).sort().join(',') : '';
  // Validate contract provenance labels, not the HTTP caller's identity.
  // judge_fixture is virtual evidence; none carries no region/network evidence.
  // Never derive or fill these fields from client headers, IPs or local time.
  const signals = body?.signals;
  const validSignals = keys(signals) === 'hour,network,region,source'
    && ['none', 'judge_fixture'].includes(signals.source)
    && ['region', 'network'].every(key => typeof signals[key] === 'string'
      && signals[key].trim().length > 0 && signals[key].length <= 512)
    && (signals.source !== 'none'
      || signals.region === 'unknown' && signals.network === 'unknown')
    && Number.isInteger(signals.hour) && signals.hour >= 0 && signals.hour <= 23;
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
      && typeof event.kind === 'string' && event.kind.trim().length > 0 && event.kind.length <= 512
      && Number.isFinite(event.ageSeconds) && event.ageSeconds >= 0
      && Number.isSafeInteger(event.count) && event.count >= 0)
    && validSignals;
}

