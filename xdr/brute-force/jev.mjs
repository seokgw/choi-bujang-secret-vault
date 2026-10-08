import { createTypeSafeProvider } from './typesafe-jev.mjs';

// Credentials remain in the server environment. No local score substitution.
let provider;
export function configureJev(adapter) { provider = adapter; }
export function isJevConfigured() { return typeof provider === 'function' || Boolean(process.env.TYPESAFE_API_KEY); }
export function aiProviderName() { return typeof provider === 'function' ? 'custom' : process.env.TYPESAFE_API_KEY ? 'typesafe-jev' : 'unconfigured'; }
export async function askJev(summary) {
  const active = provider ?? (process.env.TYPESAFE_API_KEY
    ? createTypeSafeProvider({ apiKey: process.env.TYPESAFE_API_KEY }) : undefined);
  if (typeof active !== 'function') throw new Error('Jev unavailable');
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(() => active(Object.freeze({ ...summary }))),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Review timeout')), 1000); }),
    ]);
  } finally { clearTimeout(timer); }
}
