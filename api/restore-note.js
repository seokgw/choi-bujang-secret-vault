import { createHash, timingSafeEqual } from 'node:crypto';
import { jsonHeaders, verifyRequest, bodyObject, safeOrigin } from '../src/vault-server.mjs';

// This endpoint is deliberately inactive until a server-owned, independently
// verified snapshot provider and a disposable trial-note store are supplied.
// Never accept note content, owner, snapshot or DB configuration from the caller.
const digest = content => createHash('sha256').update(content, 'utf8').digest('hex');
const validId = id => Number.isSafeInteger(id) && id > 0 && id <= 2147483647;
const validHash = hash => typeof hash === 'string' && /^[a-f0-9]{64}$/u.test(hash);
const sameHash = (a, b) => validHash(a) && validHash(b)
  && timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
const fail = (res, status, error) => res.status(status).json({ error });

export function createNoteRestoreHandler({
  verify = verifyRequest,
  origin = safeOrigin,
  loadVerifiedBackup = async () => null,
  trialStore = null,
} = {}) {
  return async function restoreNote(request, response) {
    jsonHeaders(response);
    response.setHeader('Allow', 'POST');
    if (request.method !== 'POST') return fail(response, 405, 'method_not_allowed');
    const identity = await verify(request).catch(() => null);
    if (!identity) return fail(response, 401, 'unauthorized');
    // Identity 'b' must be established by the server's judge issuer.
    if (identity.kind !== 'judge' || identity.identity !== 'b'
        || typeof identity.userId !== 'string' || !identity.runId) {
      return fail(response, 403, 'forbidden');
    }
    if (!origin(request)) return fail(response, 403, 'forbidden');
    if (Object.keys(request.query ?? {}).length) return fail(response, 400, 'invalid_request');
    const body = bodyObject(request);
    if (!body || Object.keys(body).sort().join(',') !== 'id'
        || !validId(body.id)) return fail(response, 400, 'invalid_request');
    if (!trialStore || typeof trialStore.restoreOne !== 'function') {
      return fail(response, 503, 'verified_backup_unavailable');
    }

    try {
      // The provider must verify the snapshot independently and return exactly
      // one B-owned record, plus the snapshot's previously trusted content hash.
      const backup = await loadVerifiedBackup({ runId: identity.runId, noteId: body.id,
        ownerId: identity.userId, identity: 'b' });
      if (!backup || backup.verified !== true || backup.id !== body.id
          || backup.ownerId !== identity.userId
          || typeof backup.title !== 'string' || !backup.title.trim()
          || backup.title.length > 200
          || typeof backup.content !== 'string' || !backup.content.trim()
          || backup.content.length > 10000
          || !sameHash(digest(backup.content), backup.contentSha256)) {
        return fail(response, 503, 'verified_backup_unavailable');
      }

      // Store implementation must atomically constrain both id and owner,
      // reject missing/ambiguous records, and never write audit or other notes.
      const restored = await trialStore.restoreOne({
        runId: identity.runId, id: backup.id, ownerId: backup.ownerId,
        title: backup.title, content: backup.content,
        expectedContentSha256: backup.contentSha256,
      });
      if (!restored || restored.id !== backup.id
          || restored.ownerId !== backup.ownerId
          || !sameHash(restored.contentSha256, backup.contentSha256)) {
        return fail(response, 503, 'restore_verification_failed');
      }
      return response.status(200).json({
        restored: true, id: backup.id, owner: 'b', contentSha256: backup.contentSha256,
      });
    } catch {
      return fail(response, 503, 'restore_unavailable');
    }
  };
}
export default createNoteRestoreHandler();
