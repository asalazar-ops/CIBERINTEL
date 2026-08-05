// Sincroniza el catálogo de CVEs desde CISA KEV + NVD + EPSS. Solo trae
// rangos para productos que ya están en cpe_dictionary — nunca hace un
// espejo completo de NVD (millones de CVEs irrelevantes).
//
// IMPORTANTE (verificado en el plan aprobado): NVD por `cpeName=` produce
// ~99% de falsos positivos — un CPE "runs-on" (ej. "esto corre sobre Chrome
// en cualquier versión") aparece marcado vulnerable:false en su propia
// configuración pero igual sale en los resultados de búsqueda por cpeName.
// Por eso este módulo SIEMPRE filtra localmente a `vulnerable: true` con cota
// de versión real — nunca confía en el conteo de resultados de la API como
// señal de que el producto es vulnerable.
const dbLayer = require('../db');

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const EPSS_BASE = 'https://api.first.org/data/v1/epss';
// 20s era demasiado dentro de un presupuesto total de 48s (ver
// api/cron/scan-assets.js) — una sola llamada lenta podía comerse casi
// la mitad del tiempo disponible para todo el pipeline.
const FETCH_TIMEOUT_MS = 12000;

async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/** CISA KEV — catálogo completo en un solo request, ~1.5MB. Sin auth. */
async function syncKevCatalog() {
  const resp = await fetchWithTimeout(KEV_URL);
  if (!resp.ok) throw new Error(`KEV: HTTP ${resp.status}`);
  const json = await resp.json();
  const vulns = json.vulnerabilities || [];
  if (!vulns.length) return 0;

  const CHUNK = 400;
  let total = 0;
  for (let i = 0; i < vulns.length; i += CHUNK) {
    const chunk = vulns.slice(i, i + CHUNK);
    await dbLayer.batch(chunk.map((v) => ({
      sql: `INSERT INTO cve_catalog (cve_id, in_kev, kev_date_added, kev_due_date, kev_ransomware, description, refreshed_at)
            VALUES (?, 1, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(cve_id) DO UPDATE SET
              in_kev = 1, kev_date_added = excluded.kev_date_added, kev_due_date = excluded.kev_due_date,
              kev_ransomware = excluded.kev_ransomware,
              description = COALESCE(cve_catalog.description, excluded.description),
              refreshed_at = CURRENT_TIMESTAMP`,
      args: [v.cveID, v.dateAdded || null, v.dueDate || null, v.knownRansomwareCampaignUse || 'Unknown', v.shortDescription || null],
    })));
    total += chunk.length;
  }
  return total;
}

function parseNvdConfigurations(cveItem, dictionaryProducts) {
  const ranges = [];
  const configs = cveItem?.configurations || [];
  for (const config of configs) {
    for (const node of config.nodes || []) {
      for (const match of node.cpeMatch || []) {
        if (!match.vulnerable) continue; // regla anti-FP #1: solo vulnerable:true
        const parts = (match.criteria || '').split(':');
        // cpe:2.3:a:vendor:product:version:...
        const vendor = parts[3];
        const product = parts[4];
        const versionLiteral = parts[5];
        const key = `${vendor}:${product}`;
        if (!dictionaryProducts.has(key)) continue; // solo productos del diccionario

        const hasBound = match.versionStartIncluding || match.versionStartExcluding || match.versionEndIncluding || match.versionEndExcluding;
        const hasLiteral = versionLiteral && versionLiteral !== '*' && versionLiteral !== '-';
        if (!hasBound && !hasLiteral) continue; // regla anti-FP #2: sin cota, se descarta

        ranges.push({
          cve_id: cveItem.id, cpe_vendor: vendor, cpe_product: product,
          version_exact: hasLiteral ? versionLiteral : null,
          version_start_including: match.versionStartIncluding || null,
          version_start_excluding: match.versionStartExcluding || null,
          version_end_including: match.versionEndIncluding || null,
          version_end_excluding: match.versionEndExcluding || null,
        });
      }
    }
  }
  return ranges;
}

function extractCvss(cveItem) {
  const metrics = cveItem?.metrics || {};
  const src = metrics.cvssMetricV31?.[0] || metrics.cvssMetricV30?.[0] || metrics.cvssMetricV2?.[0];
  if (!src) return { score: null, severity: null, vector: null };
  return {
    score: src.cvssData?.baseScore ?? null,
    severity: src.cvssData?.baseSeverity || src.baseSeverity || null,
    vector: src.cvssData?.vectorString || null,
  };
}

/**
 * Sincroniza rangos de versión desde NVD, filtrando SOLO a CVEs de KEV (los
 * que ya importan) y SOLO a productos del diccionario. Primera corrida:
 * pagina hasKev completo. Corridas siguientes: incremental por
 * lastModStartDate, típicamente 1 request pequeño.
 */
async function syncNvdRanges({ deadlineAt = Infinity, apiKey = '' } = {}) {
  const dict = await dbLayer.all('SELECT DISTINCT cpe_vendor, cpe_product FROM cpe_dictionary WHERE enabled = 1');
  const dictionaryProducts = new Set(dict.map((d) => `${d.cpe_vendor}:${d.cpe_product}`));
  if (!dictionaryProducts.size) return { ranges: 0, cves: 0 };

  const cursorRow = await dbLayer.get(`SELECT cursor FROM intel_source_state WHERE source = 'nvd_kev'`);
  let cursor = {};
  try { cursor = cursorRow?.cursor ? JSON.parse(cursorRow.cursor) : {}; } catch { cursor = {}; }

  const headers = apiKey ? { apiKey } : {};
  // Sin API key, NVD limita a 5 req/30s — 6s de pausa entre páginas evita
  // respuestas vacías por rate limit (verificado en el plan: 2 de 4 fallaron
  // sin pausa).
  const pauseMs = apiKey ? 700 : 6500;

  let totalRanges = 0;
  let totalCves = 0;
  let startIndex = 0;
  const resultsPerPage = 500;
  let lastModEnd = new Date().toISOString();

  const baseParams = cursor.lastModEnd
    ? `&lastModStartDate=${encodeURIComponent(cursor.lastModEnd)}&lastModEndDate=${encodeURIComponent(lastModEnd)}`
    : '';

  while (Date.now() < deadlineAt) {
    const url = `${NVD_BASE}?hasKev&resultsPerPage=${resultsPerPage}&startIndex=${startIndex}${baseParams}`;
    const resp = await fetchWithTimeout(url, { headers });
    if (!resp.ok) {
      if (resp.status === 429 || resp.status === 403) break; // rate limited: se retoma en la próxima corrida
      throw new Error(`NVD: HTTP ${resp.status}`);
    }
    const json = await resp.json();
    const vulns = json.vulnerabilities || [];
    if (!vulns.length) break;

    const allRanges = [];
    for (const { cve } of vulns) {
      totalCves++;
      const cvss = extractCvss(cve);
      allRanges.push({
        sql: `INSERT INTO cve_catalog (cve_id, published, last_modified, cvss_score, cvss_severity, cvss_vector, description, refreshed_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
              ON CONFLICT(cve_id) DO UPDATE SET
                published = excluded.published, last_modified = excluded.last_modified,
                cvss_score = excluded.cvss_score, cvss_severity = excluded.cvss_severity, cvss_vector = excluded.cvss_vector,
                description = excluded.description, refreshed_at = CURRENT_TIMESTAMP`,
        args: [cve.id, cve.published || null, cve.lastModified || null, cvss.score, cvss.severity, cvss.vector, (cve.descriptions?.[0]?.value || '').slice(0, 500)],
        __isCve: true,
      });

      const ranges = parseNvdConfigurations(cve, dictionaryProducts);
      for (const r of ranges) {
        allRanges.push({
          sql: `INSERT INTO cve_affected_ranges (cve_id, cpe_vendor, cpe_product, version_exact, version_start_including, version_start_excluding, version_end_including, version_end_excluding)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id, cpe_vendor, cpe_product, version_exact, version_start_including, version_start_excluding, version_end_including, version_end_excluding) DO NOTHING`,
          args: [r.cve_id, r.cpe_vendor, r.cpe_product, r.version_exact, r.version_start_including, r.version_start_excluding, r.version_end_including, r.version_end_excluding],
        });
        totalRanges++;
      }
    }

    const CHUNK = 400;
    for (let i = 0; i < allRanges.length; i += CHUNK) {
      await dbLayer.batch(allRanges.slice(i, i + CHUNK).map(({ sql, args }) => ({ sql, args })));
    }

    startIndex += vulns.length;
    if (startIndex >= (json.totalResults || 0)) break;
    if (Date.now() + pauseMs > deadlineAt) break;
    await new Promise((r) => setTimeout(r, pauseMs));
  }

  await dbLayer.run(
    `INSERT INTO intel_source_state (source, last_run, last_status, cursor, rows_upserted)
     VALUES ('nvd_kev', CURRENT_TIMESTAMP, 'ok', ?, ?)
     ON CONFLICT(source) DO UPDATE SET last_run = CURRENT_TIMESTAMP, last_status = 'ok', cursor = excluded.cursor, rows_upserted = excluded.rows_upserted`,
    [JSON.stringify({ lastModEnd }), totalRanges]
  );

  return { ranges: totalRanges, cves: totalCves };
}

/**
 * Sincroniza TODOS los CVEs de un producto específico del diccionario, no
 * solo los marcados hasKev. `hasKev` (syncNvdRanges arriba) solo cubre CVEs
 * explotados activamente y conocidos — un subconjunto pequeño (1657 CVEs
 * totales) que deja fuera vulnerabilidades reales de severidad alta/crítica
 * que aún no llegaron a ese catálogo. Esta función consulta NVD por
 * `virtualMatchString` para UN producto a la vez (NVD no soporta filtrar por
 * múltiples CPEs en una sola llamada), así que el volumen es proporcional al
 * número de productos del diccionario, no al tamaño de NVD — verificado en
 * vivo: Chrome (el más grande con diferencia) trae 5816 CVEs totales, la
 * mayoría de los demás productos traen decenas o cientos.
 *
 * Rota por el producto con `last_run` más antiguo (o nunca sincronizado),
 * igual patrón que `getSourcesByLastRun` en server/intel/ingest.js — así un
 * producto grande que no termine en una corrida queda primero en la cola de
 * mañana, sin lógica de rotación explícita.
 */
async function syncNvdRangesByProduct({ deadlineAt = Infinity, apiKey = '', maxProducts = 5 } = {}) {
  const dict = await dbLayer.all('SELECT DISTINCT cpe_vendor, cpe_product FROM cpe_dictionary WHERE enabled = 1');
  if (!dict.length) return { products: 0, ranges: 0, cves: 0 };

  const states = await dbLayer.all(
    `SELECT source, last_run, cursor FROM intel_source_state WHERE source LIKE 'nvd_product:%'`
  );
  const stateByKey = new Map(states.map((s) => [s.source, s]));
  const ordered = [...dict].sort((a, b) => {
    const ka = `nvd_product:${a.cpe_vendor}:${a.cpe_product}`;
    const kb = `nvd_product:${b.cpe_vendor}:${b.cpe_product}`;
    const la = stateByKey.get(ka)?.last_run || '';
    const lb = stateByKey.get(kb)?.last_run || '';
    return la.localeCompare(lb);
  });

  const headers = apiKey ? { apiKey } : {};
  const pauseMs = apiKey ? 700 : 6500;
  // BUG REAL medido en producción: con resultsPerPage=500, el chequeo del
  // tope de CVEs solo se evalúa AL INICIO de cada iteración del while — una
  // sola página ya trae 500 CVEs, cada uno con su propio parseNvdConfigurations
  // + inserts en cve_affected_ranges (Chrome: ~27 rangos por CVE en promedio,
  // verificado: 1000 CVEs -> 27420 rangos). Eso por sí solo tomó más de 40s
  // reales para solo 2 páginas, muy por encima de lo estimado. Página más
  // chica = el tope de abajo se respeta con precisión real, y cada iteración
  // individual es rápida y predecible.
  const resultsPerPage = 100;
  const dictionaryProducts = new Set(dict.map((d) => `${d.cpe_vendor}:${d.cpe_product}`));
  // Tope duro por producto por corrida, además del deadline de tiempo —
  // sin esto, un producto con historial grande (Chrome: ~5800 CVEs desde
  // 2011, verificado en vivo) monopoliza el presupuesto completo de la
  // corrida y ningún otro producto del diccionario llega a sincronizarse.
  // Retoma desde el cursor guardado (prevCursor.startIndex), así que en
  // varias corridas diarias Chrome termina su historial completo igual —
  // solo que repartido, sin acaparar ninguna corrida individual. Bajado dos
  // veces (800 -> 300 -> 150) tras medir que el tiempo real en Vercel es
  // sustancialmente mayor que en local — mejor 1-2 páginas garantizadas por
  // corrida que apuntar a un tope que nunca se alcanza sin timeout.
  const maxCvesPerProduct = 150;

  let productsDone = 0;
  let totalRanges = 0;
  let totalCves = 0;

  for (const { cpe_vendor, cpe_product } of ordered) {
    if (productsDone >= maxProducts || Date.now() > deadlineAt) break;

    const stateKey = `nvd_product:${cpe_vendor}:${cpe_product}`;
    const prevCursor = (() => {
      try { return JSON.parse(stateByKey.get(stateKey)?.cursor || '{}'); } catch { return {}; }
    })();
    const vms = `cpe:2.3:a:${cpe_vendor}:${cpe_product}`;
    let startIndex = Number.isInteger(prevCursor.startIndex) ? prevCursor.startIndex : 0;
    let productTotal = Number.isInteger(prevCursor.total) ? prevCursor.total : Infinity;
    let productError = null;
    let cvesThisProduct = 0;

    try {
      while (startIndex < productTotal && Date.now() < deadlineAt && cvesThisProduct < maxCvesPerProduct) {
        const url = `${NVD_BASE}?virtualMatchString=${encodeURIComponent(vms)}&resultsPerPage=${resultsPerPage}&startIndex=${startIndex}`;
        const resp = await fetchWithTimeout(url, { headers });
        if (!resp.ok) {
          if (resp.status === 429 || resp.status === 403) break;
          throw new Error(`HTTP ${resp.status}`);
        }
        const json = await resp.json();
        const vulns = json.vulnerabilities || [];
        productTotal = json.totalResults || 0;
        if (!vulns.length) break;

        const allRanges = [];
        for (const { cve } of vulns) {
          totalCves++;
          cvesThisProduct++;
          const cvss = extractCvss(cve);
          allRanges.push({
            sql: `INSERT INTO cve_catalog (cve_id, published, last_modified, cvss_score, cvss_severity, cvss_vector, description, refreshed_at)
                  VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                  ON CONFLICT(cve_id) DO UPDATE SET
                    published = excluded.published, last_modified = excluded.last_modified,
                    cvss_score = excluded.cvss_score, cvss_severity = excluded.cvss_severity, cvss_vector = excluded.cvss_vector,
                    description = excluded.description, refreshed_at = CURRENT_TIMESTAMP`,
            args: [cve.id, cve.published || null, cve.lastModified || null, cvss.score, cvss.severity, cvss.vector, (cve.descriptions?.[0]?.value || '').slice(0, 500)],
          });
          // Misma regla anti-falso-positivo que syncNvdRanges: solo rangos con
          // vulnerable:true y cota de versión real, filtrado a este producto
          // (dictionaryProducts aquí tiene un solo elemento relevante, pero se
          // reutiliza parseNvdConfigurations tal cual para no duplicar lógica).
          const ranges = parseNvdConfigurations(cve, dictionaryProducts);
          for (const r of ranges) {
            allRanges.push({
              sql: `INSERT INTO cve_affected_ranges (cve_id, cpe_vendor, cpe_product, version_exact, version_start_including, version_start_excluding, version_end_including, version_end_excluding)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id, cpe_vendor, cpe_product, version_exact, version_start_including, version_start_excluding, version_end_including, version_end_excluding) DO NOTHING`,
              args: [r.cve_id, r.cpe_vendor, r.cpe_product, r.version_exact, r.version_start_including, r.version_start_excluding, r.version_end_including, r.version_end_excluding],
            });
            totalRanges++;
          }
        }

        const CHUNK = 400;
        for (let i = 0; i < allRanges.length; i += CHUNK) {
          await dbLayer.batch(allRanges.slice(i, i + CHUNK).map(({ sql, args }) => ({ sql, args })));
        }

        startIndex += vulns.length;
        if (startIndex >= productTotal) break;
        if (Date.now() + pauseMs > deadlineAt) break;
        await new Promise((r) => setTimeout(r, pauseMs));
      }
    } catch (err) {
      productError = err.message;
    }

    const finishedProduct = startIndex >= productTotal || productError;
    await dbLayer.run(
      `INSERT INTO intel_source_state (source, last_run, last_status, last_error, cursor, rows_upserted)
       VALUES (?, CURRENT_TIMESTAMP, ?, ?, ?, ?)
       ON CONFLICT(source) DO UPDATE SET last_run = CURRENT_TIMESTAMP, last_status = excluded.last_status, last_error = excluded.last_error, cursor = excluded.cursor, rows_upserted = excluded.rows_upserted`,
      [stateKey, productError ? 'error' : 'ok', productError, JSON.stringify({ startIndex, total: productTotal }), totalRanges]
    );
    // Solo cuenta como "producto hecho" si terminó su paginación completa —
    // si quedó a medias por el deadline, se retoma en la próxima corrida
    // desde el mismo startIndex (no se pierde progreso, pero tampoco se
    // considera completo para efectos de rotación).
    if (finishedProduct) productsDone++;
  }

  return { products: productsDone, ranges: totalRanges, cves: totalCves };
}

/** EPSS en lotes de 100 CVEs (límite de la API), solo para los CVEs que ya tienen rangos relevantes. */
async function syncEpssScores({ deadlineAt = Infinity } = {}) {
  // Sin deadline propio, esto podía crecer sin límite: 1022 CVEs distintos ya
  // significan 11 lotes de 100 — cada corrida que amplía el catálogo (ver
  // syncNvdRangesByProduct) hace crecer este número más. Prioriza los CVEs
  // que nunca se sincronizaron (epss_updated IS NULL) antes que refrescar los
  // que ya tienen un score reciente.
  const rows = await dbLayer.all(
    `SELECT r.cve_id FROM cve_affected_ranges r
     JOIN cve_catalog c ON c.cve_id = r.cve_id
     GROUP BY r.cve_id
     ORDER BY (c.epss_updated IS NULL) DESC, c.epss_updated ASC`
  );
  if (!rows.length) return 0;

  const CHUNK = 100;
  let total = 0;
  for (let i = 0; i < rows.length; i += CHUNK) {
    if (Date.now() > deadlineAt) break;
    const ids = rows.slice(i, i + CHUNK).map((r) => r.cve_id);
    const resp = await fetchWithTimeout(`${EPSS_BASE}?cve=${ids.join(',')}`);
    if (!resp.ok) continue;
    const json = await resp.json();
    const data = json.data || [];
    if (!data.length) continue;
    await dbLayer.batch(data.map((d) => ({
      sql: `UPDATE cve_catalog SET epss_score = ?, epss_percentile = ?, epss_updated = ? WHERE cve_id = ?`,
      args: [Number(d.epss) || null, Number(d.percentile) || null, d.date || null, d.cve],
    })));
    total += data.length;
  }
  return total;
}

/**
 * Orquesta KEV -> NVD (hasKev) -> NVD por producto -> EPSS, dentro del
 * presupuesto del cron. Cada etapa se salta por completo si ya no queda
 * tiempo suficiente para que valga la pena intentarla — antes se le pasaban
 * deadlines ya vencidos "por si acaso" y la etapa igual arrancaba una
 * petición HTTP completa, que es exactamente lo que causó el
 * FUNCTION_INVOCATION_TIMEOUT real visto en producción (el cálculo de
 * presupuesto era optimista, sin chequeos intermedios).
 */
async function syncVulnCatalog({ deadlineAt, nvdApiKey = '' } = {}) {
  const result = {};

  // KEV: única etapa sin deadline propio (siempre 1 solo request), pero se
  // salta igual si ya no queda margen — sin esto, una corrida que llegara
  // aquí con <2s no tendría forma de completar ni siquiera esta descarga.
  if (Date.now() < deadlineAt - 2000) {
    try {
      result.kev = await syncKevCatalog();
    } catch (err) {
      result.kev = { error: err.message };
    }
  } else {
    result.kev = { skipped: true };
  }

  // hasKev es barato (1 request paginado) y se queda como respaldo — cubre
  // productos aún no mapeados en el diccionario que aparezcan en KEV. Con el
  // presupuesto global recortado a 30s (ver api/cron/scan-assets.js), esta
  // etapa se limita a como mucho 8s para dejar el grueso a
  // syncNvdRangesByProduct.
  if (Date.now() < deadlineAt - 5000) {
    try {
      result.nvd = await syncNvdRanges({ deadlineAt: Math.min(deadlineAt - 5000, Date.now() + 8000), apiKey: nvdApiKey });
    } catch (err) {
      result.nvd = { error: err.message };
    }
  } else {
    result.nvd = { skipped: true };
  }

  // Cobertura completa por producto — deja 2s de margen para EPSS. Sin esto,
  // productos sin CVEs en KEV (la mayoría de los que se agregaron
  // manualmente) nunca tendrían ningún rango de versión sincronizado.
  // maxProducts=1: con el presupuesto recortado, mejor completar UN producto
  // por corrida de forma confiable que intentar varios y arriesgar timeout.
  if (Date.now() < deadlineAt - 2000) {
    try {
      result.nvd_by_product = await syncNvdRangesByProduct({ deadlineAt: deadlineAt - 2000, apiKey: nvdApiKey, maxProducts: 1 });
    } catch (err) {
      result.nvd_by_product = { error: err.message };
    }
  } else {
    result.nvd_by_product = { skipped: true };
  }

  if (Date.now() < deadlineAt) {
    try {
      result.epss = await syncEpssScores({ deadlineAt });
    } catch (err) {
      result.epss = { error: err.message };
    }
  } else {
    result.epss = { skipped: true };
  }
  return result;
}

module.exports = { syncKevCatalog, syncNvdRanges, syncNvdRangesByProduct, syncEpssScores, syncVulnCatalog, parseNvdConfigurations, extractCvss };
