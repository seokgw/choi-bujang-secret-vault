import { createTypeSafeProvider } from './typesafe-jev.mjs';
import { createOllamaProvider } from './ollama.mjs';
// Explicit adapters take precedence; environment credentials remain server-side.
let provider;
let local;
let localModel;
export function configureJev(adapter) { provider = adapter; }
export function isJevConfigured() { return typeof provider === 'function' || Boolean(process.env.TYPESAFE_API_KEY); }
export function aiProviderName() { return typeof provider === 'function' ? 'custom' : process.env.OLLAMA_MODEL ? 'ollama' : process.env.TYPESAFE_API_KEY ? 'typesafe-jev' : 'unconfigured'; }
export async function askJev(summary) {
  if (process.env.OLLAMA_MODEL && localModel !== process.env.OLLAMA_MODEL) {
    localModel = process.env.OLLAMA_MODEL;
    local = createOllamaProvider({ model: localModel });
  }
  const active = provider ?? (process.env.OLLAMA_MODEL ? local : process.env.TYPESAFE_API_KEY
    ? createTypeSafeProvider({ apiKey: process.env.TYPESAFE_API_KEY }) : undefined);
  if (typeof active !== 'function') throw new Error('Jev unavailable');
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(() => active(Object.freeze({ ...summary }))),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('AI timeout')), !provider && process.env.OLLAMA_MODEL ? 56000 : 1000); }),
    ]);
  } finally { clearTimeout(timer); }
}
