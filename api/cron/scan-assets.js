// Cron diario (ver vercel.json — Hobby solo permite frecuencia diaria,
// maxDuration=60 es el tope real del plan). Comparte esa ventana entre tres
// trabajos: catálogo CVE (KEV + NVD por producto), correlación de
// vulnerabilidades pendientes, y escaneo de assets (dominios/typosquatting).
//
// CAUSA RAÍZ real de 4 timeouts consecutivos en producción (confirmada con
// Runtime Logs de Vercel, no una suposición): NO era el presupuesto del
// catálogo CVE — era `autoScanAssetsBudgeted` (código preexistente, ver
// server/app.js). Su `maxMs` solo se chequea ENTRE assets distintos, nunca
// DENTRO de un `scanDomain()` ya en curso. `scanDomain` corre 8 fuentes de
// descubrimiento de subdominios en paralelo con timeouts individuales de
// hasta 20s (crt.sh) cada una, más resolución DNS masiva después — con un
// solo asset en la cola, esto por sí solo puede agotar los 60s completos
// antes de que cualquier otro código del handler llegue a ejecutarse (visto
// en los logs: entra a autoScanAssetsBudgeted, consulta 3-4 fuentes DNS, y
// el siguiente log es "Task timed out after 60 seconds" — nunca vuelve).
//
// Fix: se invierte el orden. El catálogo CVE y la correlación (que sí
// respetan su deadline con precisión, verificado en local) van PRIMERO con
// su presupuesto garantizado; el escaneo de assets se queda al final con lo
// que sobre, así un scanDomain colgado nunca vuelve a bloquear el trabajo
// que sí es predecible.
const { withCronAuth } = require('./_helpers');
const app = require('../../server/app');

const SAFETY_MARGIN_MS = 15 * 1000;
const HARD_LIMIT_MS = 60 * 1000;
const GLOBAL_BUDGET_MS = HARD_LIMIT_MS - SAFETY_MARGIN_MS; // 45s

// Presupuesto nominal del escaneo de assets — SIGUE sin ser un límite duro
// real (autoScanAssetsBudgeted no puede interrumpir un scanDomain a mitad de
// camino), pero al ir al final ya no compite por el tiempo del catálogo CVE.
const ASSETS_SHARE_MS = 10 * 1000;

function elapsed(startedAt) { return `${Date.now() - startedAt}ms`; }

module.exports = withCronAuth('scan-assets', async () => {
  const result = {};
  const startedAt = Date.now();
  const globalDeadline = startedAt + GLOBAL_BUDGET_MS;

  console.log(`[scan-assets] handler arrancó, deadline=${GLOBAL_BUDGET_MS}ms`);

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

  // Al final, con lo que sobre. Sigue sin poder interrumpir un scanDomain a
  // mitad de camino (ver nota arriba), pero ya no bloquea nada más si se
  // cuelga — solo alarga esta invocación hasta el límite duro de Vercel.
  if (Date.now() < globalDeadline) {
    try {
      console.log(`[scan-assets] iniciando autoScanAssetsBudgeted (+${elapsed(startedAt)})`);
      result.assets = await app.jobs.autoScanAssetsBudgeted(ASSETS_SHARE_MS);
      console.log(`[scan-assets] autoScanAssetsBudgeted OK (+${elapsed(startedAt)})`);
    } catch (err) {
      console.error(`[scan-assets] autoScanAssetsBudgeted FALLÓ (+${elapsed(startedAt)}):`, err.message);
      result.assets = { error: err.message };
    }
  } else {
    result.assets = { skipped: true, reason: 'sin presupuesto restante' };
  }

  console.log(`[scan-assets] handler terminando (+${elapsed(startedAt)})`);
  return result;
});
