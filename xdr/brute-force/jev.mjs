// Local evidence policy replaces external inference. Scores are policy values,
// not calibrated AI probabilities or responses from the TypeSafe Jev service.
let provider;
export function configureJev(adapter) { provider = adapter; }
export function isJevConfigured() { return true; }
export function aiProviderName() { return typeof provider === 'function' ? 'custom' : 'local-policy'; }
function localReview(summary) {
  // Missing evidence cannot justify blocking or declaring the event normal.
  if (summary.description !== 'ambiguous-failures') return 0.5;
  const level = Number.isInteger(summary.level) ? summary.level : 5;
  return Math.min(0.7, Math.max(0.5, 0.5 + (level - 5) * 0.025));
}
export async function askJev(summary) {
  const active = provider ?? localReview;
  if (typeof active !== 'function') throw new Error('Jev unavailable');
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(() => active(Object.freeze({ ...summary }))),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Review timeout')), 1000); }),
    ]);
  } finally { clearTimeout(timer); }
}
