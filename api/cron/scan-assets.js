// Cron diario (ver vercel.json — Hobby solo permite frecuencia diaria).
// scanDomain() puede tardar 20s+ por dominio (crt.sh, cientos de variantes de
// typosquatting), así que en vez de recorrer todos los assets se trabaja con
// un presupuesto de tiempo: escanea en orden "más antiguo primero" hasta
// agotarlo, y dentro de pocas corridas diarias completa la rotación de todos
// los assets monitoreados sin arriesgar el límite de duración de la función.
const { withCronAuth } = require('./_helpers');
const app = require('../../server/app');

const MAX_BUDGET_MS = 55 * 1000;

module.exports = withCronAuth('scan-assets', async () => {
  return app.jobs.autoScanAssetsBudgeted(MAX_BUDGET_MS);
});
