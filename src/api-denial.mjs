// Short, public reason codes only; never log identities, tokens or resource bodies.
export function rejectApi(response, status, error, reason) {
  response.setHeader('X-Aleph-Denial-Reason', reason);
  return response.status(status).json({ error });
}
