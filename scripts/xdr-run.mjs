import { access, appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const MODULE_KEYS = ['brute-force', 'web-injection', 'known-cve', 'persistence', 'privilege', 'exfiltration'];
const ACTIONS = new Set(['block', 'alert', 'record']);

export function isDecision(value) {
  return Boolean(value)
    && typeof value === 'object'
    && !Array.isArray(value)
    && ACTIONS.has(value.action)
    && typeof value.confidence === 'number'
    && Number.isFinite(value.confidence)
    && value.confidence >= 0
    && value.confidence <= 1
    && typeof value.reason === 'string';
}

export async function runXdr({ root, moduleKey, writeError = (line) => console.error(line) }) {
  if (!MODULE_KEYS.includes(moduleKey)) {
    throw new Error('moduleKey 가 없습니다. brute-force, web-injection, known-cve, persistence, privilege, exfiltration 중 하나를 넣습니다.');
  }
  const fixture = JSON.parse(await readFile(join(root, 'xdr', 'fixtures', `${moduleKey}.json`), 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== moduleKey || !Array.isArray(fixture.alerts)) {
    throw new Error('경보 묶음 형식이 아닙니다.');
  }
  const loaded = await import(pathToFileURL(join(root, 'xdr', moduleKey, 'decide.mjs')).href);
  if (typeof loaded.decide !== 'function') throw new Error('decide 함수를 내보내지 않았습니다.');

  const decisions = [];
  const counts = { block: 0, alert: 0, record: 0 };
  for (const alert of fixture.alerts) {
    const alertId = alert && typeof alert.id === 'string' ? alert.id : '';
    let action = 'record';
    let confidence = 0;
    let reason = '반환 형식이 아닙니다';
    try {
      const out = await loaded.decide(alert);
      if (isDecision(out)) {
        action = out.action;
        confidence = out.confidence;
        reason = out.reason;
      } else {
        writeError(`형식 오류: ${alertId || '(id 없음)'}`);
      }
    } catch {
      writeError(`형식 오류: ${alertId || '(id 없음)'}`);
    }
    decisions.push({ alertId, action, confidence, reason });
    counts[action] += 1;
  }

  const result = { schema: 'aleph.xdr.result.v1', moduleKey, decisions, counts };
  // The base runner must work in isolation with just the fixture and decide.
  // Repository-specific ZTNA replay is optional enrichment, not a prerequisite.
  const replayPaths = ['scripts/fixture-7.mjs', 'xdr/brute-force/ztna.mjs',
    'xdr/brute-force/read-alerts.mjs', 'xdr/brute-force/jev.mjs'];
  const replayAvailable = moduleKey === 'brute-force' && (await Promise.all(
    replayPaths.map(path => access(join(root, path)).then(() => true, () => false))
  )).every(Boolean);
  if (replayAvailable) {
    const { fixtureRequests } = await import(pathToFileURL(join(root, 'scripts/fixture-7.mjs')).href);
    const { createDenyRules, decideWithDenyRules } = await import(pathToFileURL(join(root, 'xdr/brute-force/ztna.mjs')).href);
    const { readAlerts } = await import(pathToFileURL(join(root, 'xdr/brute-force/read-alerts.mjs')).href);
    const { isJevConfigured, aiProviderName } = await import(pathToFileURL(join(root, 'xdr/brute-force/jev.mjs')).href);
    const extracted = await readAlerts(join(root, 'xdr', 'fixtures', 'brute-force.json'));
    const rules = createDenyRules(fixture.alerts, decisions);
    const checks = [];
    for (let i = 0; i < fixture.alerts.length; i += 1) {
      const alert = fixture.alerts[i];
      const decision = await decideWithDenyRules(fixtureRequests().normal, {
        trustedSource: extracted[i].source, rules, now: Date.parse(extracted[i].timestamp),
      });
      checks.push({ alertId: alert.id, decision: decision.decision,
        dynamicDeny: decision.ruleIds.includes('xdr.brute-force.deny') });
    }
    result.validation = {
      rawCount: fixture.alerts.length, extractedCount: extracted.length,
      normalBlocked: decisions.filter((d, i) => extracted[i].description === 'normal-event' && d.action === 'block').length,
      normalZtnaDenied: checks.filter((d, i) => extracted[i].description === 'normal-event' && d.decision === 'deny').length,
      productionConnected: false, jevConfigured: isJevConfigured(),
      aiProvider: aiProviderName(),
    };
    result.ztna = { scope: 'fixture replay with trusted source; existing starter denies all requests', rules, checks };
  }
  if (moduleKey === 'web-injection') {
    const paths = ['xdr/web-injection/ztna.mjs', 'xdr/web-injection/read-alerts.mjs'];
    if ((await Promise.all(paths.map(path => access(join(root, path)).then(() => true, () => false)))).every(Boolean)) {
      const { createDenyRules } = await import(pathToFileURL(join(root, paths[0])).href);
      const { readAlerts } = await import(pathToFileURL(join(root, paths[1])).href);
      const extracted = await readAlerts(join(root, 'xdr/fixtures/web-injection.json'));
      // No production identity bindings exist in the training alerts.
      result.ztna = { scope: 'unbound candidates; trusted user bindings required',
        candidates: decisions.filter(d => d.action === 'block').map(d => ({
          action: d.action, confidence: d.confidence, pattern: d.reason, alertId: d.alertId,
          issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
        })),
        rules: createDenyRules(decisions, []).rules };
      result.validation = { rawCount: fixture.alerts.length, extractedCount: extracted.length,
        productionConnected: false };
    }
  }
  if (moduleKey === 'brute-force' || moduleKey === 'web-injection') {
    for (const d of decisions.filter(d => d.action !== 'record')) {
      await appendFile(join(root, 'xdr', 'alerts.log'), `${JSON.stringify({ runAt: new Date().toISOString(), ...(moduleKey === 'web-injection' ? { moduleKey } : {}), ...d })}\n`, 'utf8');
    }
  }
  const outDir = join(root, 'xdr', moduleKey);
  await mkdir(outDir, { recursive: true });
  await writeFile(join(outDir, 'result.json'), `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  return result;
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..');
  try {
    await runXdr({ root, moduleKey: process.argv[2] });
  } catch (error) {
    console.error(error instanceof Error ? error.message : '실행 오류');
    process.exitCode = 1;
  }
}
