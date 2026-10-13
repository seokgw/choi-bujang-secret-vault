export default function handler(request, response) { response.status(503).json({ error: 'evidence_unavailable' }); }
