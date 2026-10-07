// Install a trusted Jev adapter in the host process; no endpoint or credential is invented.
let provider;
export function configureJev(adapter) { provider = adapter; }
export async function askJev(summary) {
  if (typeof provider !== 'function') throw new Error('Jev unavailable');
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(() => provider(Object.freeze({ ...summary }))),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Jev timeout')), 1000); }),
    ]);
  } finally { clearTimeout(timer); }
}
