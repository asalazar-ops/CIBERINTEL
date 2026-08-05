// Cron diario (ver vercel.json — Hobby solo permite frecuencia diaria,
// maxDuration=60 es el tope real del plan). Comparte esa ventana entre tres
// trabajos: escaneo de assets, catálogo CVE (KEV + NVD por producto), y
// correlación de vulnerabilidades pendientes.
//
// BUG REAL encontrado en producción: un primer reparto "en papel" (15s+40s=
// 55s) causó un FUNCTION_INVOCATION_TIMEOUT real de Vercel — el cálculo
// asumía que cada etapa respetaba su ventana exacta, pero no hay margen para
// el overhead real (cold start, latencia a Turso, la propia llamada HTTP a
// NVD en curso cuando se agota el tiempo). Rediseñado con UN SOLO deadline
// global, con margen de seguridad explícito reservado al final para que la
// función pueda devolver una respuesta antes de que Vercel la mate — sin
// esto, ni siquiera queda registro en cron_runs de qué pasó.
const { withCronAuth } = require('./_helpers');
const app = require('../../server/app');

// 12s de margen real: cubre cold start + el tramo final de cualquier fetch
// en curso que no pueda abortarse a mitad de camino. Verificado que sin
// margen (o con uno de ~5s) la función igual se pasa del límite duro.
const SAFETY_MARGIN_MS = 12 * 1000;
const HARD_LIMIT_MS = 60 * 1000;
const GLOBAL_BUDGET_MS = HARD_LIMIT_MS - SAFETY_MARGIN_MS; // 48s

const ASSETS_SHARE_MS = 10 * 1000;

module.exports = withCronAuth('scan-assets', async () => {
  const result = {};
  const startedAt = Date.now();
  const globalDeadline = startedAt + GLOBAL_BUDGET_MS;

  try {
    result.assets = await app.jobs.autoScanAssetsBudgeted(ASSETS_SHARE_MS);
  } catch (err) {
    result.assets = { error: err.message };
  }

  try {
    result.vuln_catalog = await app.jobs.syncVulnCatalog({
      deadlineAt: globalDeadline,
      nvdApiKey: process.env.NVD_API_KEY || '',
    });
  } catch (err) {
    result.vuln_catalog = { error: err.message };
  }

  // Solo corre si de verdad queda presupuesto — antes se le pasaba un
  // deadline ya vencido de todas formas, y aun así arrancaba una iteración.
  if (Date.now() < globalDeadline) {
    try {
      result.vuln_correlation = await app.jobs.correlateAllPending({ limit: 25, deadlineAt: globalDeadline });
    } catch (err) {
      result.vuln_correlation = { error: err.message };
    }
  } else {
    result.vuln_correlation = { skipped: true, reason: 'sin presupuesto restante' };
  }

  return result;
});
