// Cron diario (ver vercel.json — Hobby solo permite frecuencia diaria,
// maxDuration=60 es el tope real del plan). Comparte esa ventana entre tres
// trabajos: escaneo de assets, catálogo CVE (KEV + NVD por producto), y
// correlación de vulnerabilidades pendientes.
//
// BUG REAL encontrado en producción, en DOS intentos: un primer reparto "en
// papel" (15s+40s=55s) causó un FUNCTION_INVOCATION_TIMEOUT real de Vercel.
// Un segundo intento con deadline global de 48s (que localmente medía 42.8s
// real) TAMBIÉN dio timeout en Vercel — ni siquiera llegó a persistir el
// progreso del primer producto en intel_source_state, lo que confirma que
// el tiempo real en el entorno de Vercel (latencia a NVD/Turso desde su
// datacenter) es sustancialmente mayor que en local. No hay forma de medir
// esto con precisión sin instrumentación en logs de Vercel, así que el
// presupuesto se recorta de forma deliberadamente conservadora — mejor una
// corrida corta y segura que se repite muchas veces, que una que apunta al
// límite y falla sin dejar rastro.
const { withCronAuth } = require('./_helpers');
const app = require('../../server/app');

const SAFETY_MARGIN_MS = 30 * 1000;
const HARD_LIMIT_MS = 60 * 1000;
const GLOBAL_BUDGET_MS = HARD_LIMIT_MS - SAFETY_MARGIN_MS; // 30s

const ASSETS_SHARE_MS = 6 * 1000;

// Logging explícito por etapa — tres timeouts consecutivos en Vercel (con
// presupuestos nominales de 55s, 48s y 30s, ninguno acercándose siquiera a
// persistir el progreso del primer producto) hacen sospechar que el problema
// no es de presupuesto mal calculado sino de algo colgándose por completo
// antes de la primera etapa medible. Sin esto, los Runtime Logs de Vercel no
// dan ninguna pista de en qué línea se detiene la ejecución.
function elapsed(startedAt) { return `${Date.now() - startedAt}ms`; }

module.exports = withCronAuth('scan-assets', async () => {
  const result = {};
  const startedAt = Date.now();
  const globalDeadline = startedAt + GLOBAL_BUDGET_MS;

  console.log(`[scan-assets] handler arrancó, deadline=${GLOBAL_BUDGET_MS}ms`);

  try {
    console.log(`[scan-assets] iniciando autoScanAssetsBudgeted (+${elapsed(startedAt)})`);
    result.assets = await app.jobs.autoScanAssetsBudgeted(ASSETS_SHARE_MS);
    console.log(`[scan-assets] autoScanAssetsBudgeted OK (+${elapsed(startedAt)})`);
  } catch (err) {
    console.error(`[scan-assets] autoScanAssetsBudgeted FALLÓ (+${elapsed(startedAt)}):`, err.message);
    result.assets = { error: err.message };
  }

  try {
    console.log(`[scan-assets] iniciando syncVulnCatalog (+${elapsed(startedAt)})`);
    result.vuln_catalog = await app.jobs.syncVulnCatalog({
      deadlineAt: globalDeadline,
      nvdApiKey: process.env.NVD_API_KEY || '',
    });
    console.log(`[scan-assets] syncVulnCatalog OK (+${elapsed(startedAt)}):`, JSON.stringify(result.vuln_catalog));
  } catch (err) {
    console.error(`[scan-assets] syncVulnCatalog FALLÓ (+${elapsed(startedAt)}):`, err.message);
    result.vuln_catalog = { error: err.message };
  }

  // Solo corre si de verdad queda presupuesto — antes se le pasaba un
  // deadline ya vencido de todas formas, y aun así arrancaba una iteración.
  if (Date.now() < globalDeadline) {
    try {
      console.log(`[scan-assets] iniciando correlateAllPending (+${elapsed(startedAt)})`);
      result.vuln_correlation = await app.jobs.correlateAllPending({ limit: 25, deadlineAt: globalDeadline });
      console.log(`[scan-assets] correlateAllPending OK (+${elapsed(startedAt)})`);
    } catch (err) {
      console.error(`[scan-assets] correlateAllPending FALLÓ (+${elapsed(startedAt)}):`, err.message);
      result.vuln_correlation = { error: err.message };
    }
  } else {
    result.vuln_correlation = { skipped: true, reason: 'sin presupuesto restante' };
  }

  console.log(`[scan-assets] handler terminando (+${elapsed(startedAt)})`);
  return result;
});
