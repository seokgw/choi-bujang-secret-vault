// Contract: https://docs.typesafe.ai/api (TypeSafe's first-party endpoint).
export const ENDPOINT = 'https://api.typesafe.ai/v1/systemone';

export function createTypeSafeProvider({ apiKey, fetchImpl = fetch } = {}) {
  return async summary => {
    if (!apiKey) throw new Error('Jev not configured');
    const res = await fetchImpl(ENDPOINT, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(900),
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'jev-latest',
        state: {
          signal: ['ambiguous-failures', 'unknown'].includes(summary.description) ? summary.description : 'unknown',
          ruleLevel: Number.isInteger(summary.level) ? summary.level : null,
          context: 'Local attack patterns were inconclusive. Missing evidence must not be assumed. No credentials or event text provided.',
        },
        questions: {
          brute_force: {
            type: 'noul',
            instructions: 'Does the provided evidence establish a brute-force login attack?',
            criteria: {
              true: 'Evidence explicitly establishes rapid repeated login failures or the same password attempted across multiple accounts.',
              false: 'Ordinary activity, insufficient evidence, or ambiguous failures. Rule severity alone does not establish an attack.',
            },
          },
        },
      }),
    });
    if (!res.ok) throw new Error(`Jev HTTP ${res.status}`);
    const answer = (await res.json())?.answers?.brute_force;
    if (answer?.type !== 'noul' || !Number.isFinite(answer.noul) || answer.noul < 0 || answer.noul > 1) {
      throw new Error('Jev invalid answer');
    }
    // Noul is P(attack), not the separate Choice/Score confidence property.
    return answer.noul;
  };
}
