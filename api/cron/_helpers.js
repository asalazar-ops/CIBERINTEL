// Helper compartido por los handlers de /api/cron/*. Estas son funciones
// Vercel nativas (req, res) — no pasan por el middleware de Express en
// server/app.js — así que cada una valida CRON_SECRET por su cuenta.
require('dotenv').config();
const crypto = require('crypto');

const CRON_SECRET = process.env.CRON_SECRET || '';

/** true si la petición trae el Bearer token correcto. Falla cerrado si no hay secreto configurado. */
function isAuthorizedCronRequest(req) {
  const header = req.headers.authorization || '';
  const received = header.startsWith('Bearer ') ? header.slice(7) : '';
  const a = Buffer.from(received);
  const b = Buffer.from(CRON_SECRET);
  return CRON_SECRET.length > 0 && a.length === b.length && crypto.timingSafeEqual(a, b);
}

/**
 * Envuelve un handler de cron: valida el secreto, registra éxito/fallo en
 * cron_runs, y responde JSON de forma consistente. `jobName` debe coincidir
 * con el nombre usado en el dashboard para mostrar el estado de cada job.
 */
function withCronAuth(jobName, handler) {
  return async (req, res) => {
    if (!isAuthorizedCronRequest(req)) {
      console.warn(`[CRON] ⛔ Petición no autorizada a ${jobName} desde ${req.headers['x-forwarded-for'] || 'origen desconocido'}`);
      return res.status(403).json({ error: 'No autorizado' });
    }

    const { cronRuns } = require('../../server/store');
    try {
      const result = await handler(req, res);
      await cronRuns.recordSuccess(jobName, typeof result === 'string' ? result : JSON.stringify(result || {}));
      if (!res.headersSent) res.status(200).json({ success: true, job: jobName, result });
    } catch (err) {
      console.error(`[CRON] ✗ ${jobName} falló:`, err.message);
      await cronRuns.recordFailure(jobName, err.message).catch(() => {});
      if (!res.headersSent) res.status(500).json({ success: false, job: jobName, error: err.message });
    }
  };
}

module.exports = { withCronAuth };
