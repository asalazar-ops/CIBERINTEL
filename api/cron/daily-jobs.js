// Cron diario único (ver vercel.json) — el plan Hobby de Vercel limita a 2
// cron jobs y solo con frecuencia diaria, así que refresh-feeds, refresh-otx
// y cleanup-telemetry (antes 3 crons separados a 6h/1h/24h) se consolidan
// aquí. Los tres son rápidos (fetch HTTP + escritura en Turso, sin scans DNS
// largos), así que caben sin riesgo en una sola invocación.
const { withCronAuth } = require('./_helpers');
const app = require('../../server/app');

module.exports = withCronAuth('daily-jobs', async () => {
  const result = {};

  try {
    const feedStatus = await app.jobs.refreshAllFeeds();
    result.feeds = {
      ok: Object.values(feedStatus).filter(s => s.status === 'ok').length,
      error: Object.values(feedStatus).filter(s => s.status === 'error').length,
    };
  } catch (err) {
    result.feeds = { error: err.message };
  }

  if (process.env.OTX_API_KEY) {
    try {
      const fresh = await app.jobs.refreshOTXData();
      result.otx = { pulses: fresh.pulses.length, indicators: fresh.indicators.length };
    } catch (err) {
      result.otx = { error: err.message };
    }
  } else {
    result.otx = { skipped: true, reason: 'OTX_API_KEY no configurada' };
  }

  try {
    result.telemetry_deleted_rows = await app.jobs.cleanupTelemetry();
  } catch (err) {
    result.cleanup_error = err.message;
  }

  return result;
});
