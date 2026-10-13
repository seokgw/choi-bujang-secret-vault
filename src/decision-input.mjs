const decisionKeys = ['schema', 'requestId', 'classId', 'projectId', 'subjectId', 'deviceId',
  'service', 'method', 'path', 'route', 'queryLength', 'querySha256', 'at', 'policyRevision',
  'deviceRegistered', 'stepUp', 'recentEvents', 'signals'].sort().join(',');

export function decisionInput(body) {
  const keys = value => value && typeof value === 'object' && !Array.isArray(value)
    ? Object.keys(value).sort().join(',') : '';
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
      && typeof event.kind === 'string' && Number.isFinite(event.ageSeconds) && event.ageSeconds >= 0
      && Number.isSafeInteger(event.count) && event.count >= 0)
    && keys(body.signals) === 'hour,network,region,source'
    && ['source', 'region', 'network'].every(key => typeof body.signals[key] === 'string')
    && Number.isInteger(body.signals.hour) && body.signals.hour >= 0 && body.signals.hour <= 23;
}

