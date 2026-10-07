// Local only: https://docs.ollama.com/api/generate
export function createOllamaProvider({ model, fetchImpl = fetch } = {}) {
  const cache = new Map();
  return async summary => {
    if (!model || !/^[a-zA-Z0-9._:/-]+$/.test(model)) throw new Error('Ollama model missing');
    const state = { signal: summary.description === 'ambiguous-failures' ? 'ambiguous-failures' : 'unknown',
      ruleLevel: Number.isInteger(summary.level) ? summary.level : null };
    const key = JSON.stringify(state);
    if (cache.has(key)) return cache.get(key);
    const response = await fetchImpl('http://127.0.0.1:11434/api/generate', {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(55000),
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, stream: false, think: false,
        format: { type: 'object', properties: { score: { type: 'number', minimum: 0, maximum: 1 } }, required: ['score'], additionalProperties: false },
        system: 'Return JSON with score (0 to 1) estimating support for a brute-force attack. Only explicit rapid repeated login failures or same password across many accounts support an attack. Missing evidence and rule severity alone are insufficient. This score is not a calibrated probability. Do not invent evidence.',
        prompt: key, options: { temperature: 0, num_predict: 40 },
      }),
    });
    if (!response.ok) throw new Error('Ollama request failed');
    const envelope = await response.json();
    if (envelope.done !== true) throw new Error('Ollama incomplete');
    const result = JSON.parse(envelope.response);
    if (!Number.isFinite(result.score) || result.score < 0 || result.score > 1) throw new Error('Ollama invalid score');
    cache.set(key, result.score);
    return result.score;
  };
}
