// Cron diario (ver vercel.json — Hobby solo permite frecuencia diaria).
// Comparte la ventana de 60s (maxDuration en vercel.json) entre dos trabajos
// independientes: escaneo de assets (ya existía) y sincronización/correlación
// de vulnerabilidades (Fase 4, nuevo). Antes el escaneo de assets tenía todo
// el presupuesto (55s); se recorta a 30s para dejar espacio real al catálogo
// CVE — sigue rotando igual entre corridas diarias, solo más despacio.
const { withCronAuth } = require('./_helpers');
const app = require('../../server/app');

const ASSETS_BUDGET_MS = 30 * 1000;
const VULN_BUDGET_MS = 25 * 1000;

module.exports = withCronAuth('scan-assets', async () => {
  const result = {};
  const startedAt = Date.now();

  try {
    result.assets = await app.jobs.autoScanAssetsBudgeted(ASSETS_BUDGET_MS);
  } catch (err) {
    result.assets = { error: err.message };
  }

  const vulnDeadline = Date.now() + VULN_BUDGET_MS;
  try {
    result.vuln_catalog = await app.jobs.syncVulnCatalog({
      deadlineAt: vulnDeadline,
      nvdApiKey: process.env.NVD_API_KEY || '',
    });
  } catch (err) {
    result.vuln_catalog = { error: err.message };
  }

  try {
    result.vuln_correlation = await app.jobs.correlateAllPending({ limit: 25, deadlineAt: startedAt + ASSETS_BUDGET_MS + VULN_BUDGET_MS });
  } catch (err) {
    result.vuln_correlation = { error: err.message };
  }

  return result;
});
