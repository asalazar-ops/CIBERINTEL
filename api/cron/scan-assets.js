// Cron diario (ver vercel.json — Hobby solo permite frecuencia diaria).
// Comparte la ventana de 60s (maxDuration en vercel.json) entre dos trabajos
// independientes: escaneo de assets (ya existía) y sincronización/correlación
// de vulnerabilidades (Fase 4). Recortado de 30s a 15s tras ampliar el
// catálogo CVE más allá de hasKev (ver syncNvdRangesByProduct en
// server/vuln/catalog.js) — sin eso, la primera corrida real ya tardaba
// 57.2s de 60s solo con la sincronización antigua (más chica). El escaneo
// de assets sigue rotando "más antiguo primero", así que con menos tiempo
// por corrida solo tarda más días en cubrir todos los assets, no deja de
// cubrirlos.
const { withCronAuth } = require('./_helpers');
const app = require('../../server/app');

const ASSETS_BUDGET_MS = 15 * 1000;
const VULN_BUDGET_MS = 40 * 1000;

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
