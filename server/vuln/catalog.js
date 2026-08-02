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
const FETCH_TIMEOUT_MS = 20000;

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

/** EPSS en lotes de 100 CVEs (límite de la API), solo para los CVEs que ya tienen rangos relevantes. */
async function syncEpssScores() {
  const rows = await dbLayer.all('SELECT DISTINCT cve_id FROM cve_affected_ranges');
  if (!rows.length) return 0;

  const CHUNK = 100;
  let total = 0;
  for (let i = 0; i < rows.length; i += CHUNK) {
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

/** Orquesta KEV -> NVD -> EPSS dentro del presupuesto del cron. */
async function syncVulnCatalog({ deadlineAt, nvdApiKey = '' } = {}) {
  const result = {};
  try {
    result.kev = await syncKevCatalog();
  } catch (err) {
    result.kev = { error: err.message };
  }
  try {
    result.nvd = await syncNvdRanges({ deadlineAt: deadlineAt - 3000, apiKey: nvdApiKey });
  } catch (err) {
    result.nvd = { error: err.message };
  }
  if (Date.now() < deadlineAt) {
    try {
      result.epss = await syncEpssScores();
    } catch (err) {
      result.epss = { error: err.message };
    }
  }
  return result;
}

module.exports = { syncKevCatalog, syncNvdRanges, syncEpssScores, syncVulnCatalog, parseNvdConfigurations, extractCvss };
