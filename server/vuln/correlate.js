// Correlación local, sin red: compara el inventario de software de un
// endpoint (ya recolectado por el sensor) contra cve_affected_ranges (ya
// sincronizado por server/vuln/catalog.js desde KEV+NVD). Todo el trabajo de
// red pasado — esto es puro SQL + comparación de versiones en JS, por eso
// puede dispararse on-demand (POST /api/vulns/recompute/:agent_id) sin
// preocuparse por límites de tasa de APIs externas.
const crypto = require('crypto');
const dbLayer = require('../db');
const { normalizeProductName, matchToCpe } = require('./dictionary');

/**
 * Compara dos versiones estilo Windows (ej. "120.0.6099.129", "23.01",
 * "3.4.5"). Devuelve -1/0/1, o null si no se puede ordenar de forma
 * inequívoca (formatos incompatibles) — null es una señal explícita de "no
 * comparar", no un empate.
 */
function compareVersions(a, b) {
  if (!a || !b) return null;
  const clean = (v) => v.replace(/^[vV]/, '').trim();
  const pa = clean(a).split(/[.\-]/);
  const pb = clean(b).split(/[.\-]/);
  if (pa.some((p) => !/^\d+$/.test(p)) || pb.some((p) => !/^\d+$/.test(p))) return null;

  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const na = Number(pa[i] || 0);
    const nb = Number(pb[i] || 0);
    if (na !== nb) return na < nb ? -1 : 1;
  }
  return 0;
}

/**
 * ¿La versión instalada cae dentro del rango vulnerable? Reglas anti-falso-
 * positivo del plan: sin ninguna cota, se descarta (nunca "afecta a todas las
 * versiones"); versionEndExcluding sin cota inferior solo se acepta si el
 * primer segmento (tren mayor) coincide, para no reportar "Chrome 120 < CVE
 * con cota 10.0.648.134" (productos distintos con el mismo vendor:product por
 * error de mapeo, o CVEs de versiones muy antiguas que no aplican al tren
 * actual).
 */
function versionMatchesRange(installed, range) {
  if (range.version_exact) {
    return compareVersions(installed, range.version_exact) === 0 ? '== ' + range.version_exact : null;
  }

  const hasLower = range.version_start_including || range.version_start_excluding;
  const hasUpper = range.version_end_including || range.version_end_excluding;
  if (!hasLower && !hasUpper) return null; // sin cota: se descarta, no se asume universal

  if (!hasLower && hasUpper) {
    const installedMajor = installed.split('.')[0];
    const upperVersion = range.version_end_excluding || range.version_end_including;
    const upperMajor = upperVersion.split('.')[0];
    if (installedMajor !== upperMajor) return null;
  }

  if (range.version_start_including) {
    const cmp = compareVersions(installed, range.version_start_including);
    if (cmp === null || cmp < 0) return null;
  }
  if (range.version_start_excluding) {
    const cmp = compareVersions(installed, range.version_start_excluding);
    if (cmp === null || cmp <= 0) return null;
  }
  if (range.version_end_including) {
    const cmp = compareVersions(installed, range.version_end_including);
    if (cmp === null || cmp > 0) return null;
    return `<= ${range.version_end_including}`;
  }
  if (range.version_end_excluding) {
    const cmp = compareVersions(installed, range.version_end_excluding);
    if (cmp === null || cmp >= 0) return null;
    return `< ${range.version_end_excluding}`;
  }
  return `>= ${range.version_start_including || range.version_start_excluding}`;
}

function hashSoftware(softwareList) {
  const normalized = JSON.stringify(
    (softwareList || []).map((s) => `${s.name}|${s.version}`).sort()
  );
  return crypto.createHash('sha1').update(normalized).digest('hex');
}

/**
 * Correlaciona el inventario completo de un endpoint. Marca como 'resolved'
 * los hallazgos previos que no se reconfirman en esta pasada (el software se
 * desinstaló, o se actualizó fuera del rango vulnerable).
 */
async function correlateEndpoint(agentId) {
  const row = await dbLayer.get('SELECT software_info FROM sensor_endpoints WHERE agent_id = ?', [agentId]);
  if (!row || !row.software_info) return { findings: 0, unmapped: 0 };

  let software;
  try { software = JSON.parse(row.software_info); } catch { software = []; }
  if (!Array.isArray(software)) software = [];

  const findings = [];
  const unmapped = [];
  const confirmedKeys = new Set();

  for (const item of software) {
    const name = item.name;
    const version = item.version;
    if (!name || !version) continue;

    const cpe = await matchToCpe(name, item.publisher);
    if (!cpe) {
      unmapped.push({ name_normalized: normalizeProductName(name) || name.toLowerCase(), sample_name: name, sample_publisher: item.publisher || null, sample_version: version, reason: 'no_dictionary_entry' });
      continue;
    }

    const ranges = await dbLayer.all(
      'SELECT * FROM cve_affected_ranges WHERE cpe_vendor = ? AND cpe_product = ?',
      [cpe.cpe_vendor, cpe.cpe_product]
    );
    for (const range of ranges) {
      const matchedRule = versionMatchesRange(version, range);
      if (!matchedRule) continue;

      confirmedKeys.add(`${range.cve_id}|${cpe.cpe_product}|${version}`);
      findings.push({ cve_id: range.cve_id, product_name: name, product_version: version, cpe_vendor: cpe.cpe_vendor, cpe_product: cpe.cpe_product, match_confidence: cpe.confidence, matched_rule: matchedRule });
    }
  }

  if (findings.length) {
    await dbLayer.batch(findings.map((f) => ({
      sql: `INSERT INTO endpoint_vulnerabilities (agent_id, cve_id, product_name, product_version, cpe_vendor, cpe_product, match_confidence, matched_rule, status, last_confirmed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', CURRENT_TIMESTAMP)
            ON CONFLICT(agent_id, cve_id, cpe_product, product_version) DO UPDATE SET
              status = 'open', last_confirmed = CURRENT_TIMESTAMP, matched_rule = excluded.matched_rule`,
      args: [agentId, f.cve_id, f.product_name, f.product_version, f.cpe_vendor, f.cpe_product, f.match_confidence, f.matched_rule],
    })));
  }

  // Lo no reconfirmado en esta pasada pasa a 'resolved' — comparación exacta
  // por (cve_id, product, version): si la versión cambió, el hallazgo viejo
  // ya no aplica a lo instalado ahora mismo.
  const previouslyOpen = await dbLayer.all(`SELECT id, cve_id, cpe_product, product_version FROM endpoint_vulnerabilities WHERE agent_id = ? AND status = 'open'`, [agentId]);
  const toResolve = previouslyOpen.filter((p) => !confirmedKeys.has(`${p.cve_id}|${p.cpe_product}|${p.product_version}`));
  if (toResolve.length) {
    await dbLayer.batch(toResolve.map((p) => ({
      sql: `UPDATE endpoint_vulnerabilities SET status = 'resolved' WHERE id = ?`,
      args: [p.id],
    })));
  }

  if (unmapped.length) {
    await dbLayer.batch(unmapped.map((u) => ({
      sql: `INSERT INTO unmapped_software (name_normalized, sample_name, sample_publisher, sample_version, reason, last_seen)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(name_normalized) DO UPDATE SET
              sample_version = excluded.sample_version, endpoint_count = endpoint_count + 1, last_seen = CURRENT_TIMESTAMP`,
      args: [u.name_normalized, u.sample_name, u.sample_publisher, u.sample_version, u.reason],
    })));
  }

  await dbLayer.run(`UPDATE sensor_endpoints SET vuln_state = 'ok', last_correlated = CURRENT_TIMESTAMP WHERE agent_id = ?`, [agentId]);

  return { findings: findings.length, unmapped: unmapped.length, resolved: toResolve.length };
}

/** Correlaciona todos los endpoints con vuln_state='pending', hasta agotar el presupuesto o el límite. */
async function correlateAllPending({ limit = 25, deadlineAt = Infinity } = {}) {
  const pending = await dbLayer.all(`SELECT agent_id FROM sensor_endpoints WHERE vuln_state = 'pending' OR vuln_state IS NULL LIMIT ?`, [limit]);
  const results = [];
  for (const { agent_id } of pending) {
    if (Date.now() > deadlineAt) break;
    try {
      const r = await correlateEndpoint(agent_id);
      results.push({ agent_id, ...r });
    } catch (err) {
      results.push({ agent_id, error: err.message });
    }
  }
  return results;
}

module.exports = { compareVersions, versionMatchesRange, correlateEndpoint, correlateAllPending, hashSoftware };
