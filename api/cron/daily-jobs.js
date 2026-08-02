// Cron diario único (ver vercel.json) — el plan Hobby de Vercel limita a 2
// cron jobs y solo con frecuencia diaria, así que refresh-feeds, refresh-otx,
// cleanup y el motor de inteligencia multi-fuente (Fase 3) se consolidan
// aquí. maxDuration=60 en vercel.json (antes corría con el default de 10s,
// que ya rozaba el límite solo con feeds+OTX+cleanup).
const { withCronAuth } = require('./_helpers');
const app = require('../../server/app');

// Presupuesto de la fase de inteligencia dentro de la ventana de 60s: deja
// margen para feeds+OTX (~10s) y cleanup (~1s) antes del límite duro de
// Vercel. Si una fuente no alcanza a terminar, queda primera en la cola de
// mañana (ver server/intel/ingest.js: getSourcesByLastRun).
const INTEL_BUDGET_MS = 42_000;

module.exports = withCronAuth('daily-jobs', async () => {
  const result = {};
  const startedAt = Date.now();

  try {
    const feedStatus = await app.jobs.refreshAllFeeds();
    result.feeds = {
      ok: Object.values(feedStatus).filter(s => s.status === 'ok').length,
      error: Object.values(feedStatus).filter(s => s.status === 'error').length,
    };
  } catch (err) {
    result.feeds = { error: err.message };
  }

  let otxIndicators = [];
  if (process.env.OTX_API_KEY) {
    try {
      const fresh = await app.jobs.refreshOTXData();
      result.otx = { pulses: fresh.pulses.length, indicators: fresh.indicators.length };
      otxIndicators = fresh.indicators;
    } catch (err) {
      result.otx = { error: err.message };
    }
  } else {
    result.otx = { skipped: true, reason: 'OTX_API_KEY no configurada' };
  }

  // Ingesta de IOCs (Tor, Feodo, ThreatFox, MalwareBazaar, URLhaus, OTX) +
  // retro-correlación contra lo ya observado por los sensores. Sin
  // ABUSECH_AUTH_KEY, ThreatFox y MalwareBazaar simplemente no aportan filas
  // (ver server/intel/sources.js) — el resto de fuentes sigue funcionando.
  try {
    result.intel = await app.jobs.ingestAllSources({
      deadlineAt: startedAt + INTEL_BUDGET_MS,
      otxIndicators,
      abuseChAuthKey: process.env.ABUSECH_AUTH_KEY || '',
    });
  } catch (err) {
    result.intel = { error: err.message };
  }

  try {
    const retro = await app.jobs.runRetroCorrelation();
    result.retro = { newDetections: retro.newDetections };
    if (retro.byAgentScore) {
      for (const [agentId, score] of retro.byAgentScore) {
        await app.jobs.refreshBehaviorScore(agentId, score).catch(() => {});
      }
    }
  } catch (err) {
    result.retro = { error: err.message };
  }

  try {
    result.retention = await app.jobs.cleanupRetention();
  } catch (err) {
    result.cleanup_error = err.message;
  }

  return result;
});
