// Orquesta la ingesta de todas las fuentes dentro del presupuesto de tiempo
// del cron diario. Cada fuente se intenta en orden de "quién lleva más tiempo
// sin correr" — así una fuente que no alcanzó a terminar hoy queda primera en
// la cola mañana, sin necesidad de lógica de rotación explícita.
const dbLayer = require('../db');
const sources = require('./sources');

const SOURCE_ORDER = ['torexit', 'feodo', 'threatfox', 'malwarebazaar', 'urlhaus', 'otx'];

/** INSERT...ON CONFLICT en lotes — evitar un round-trip a Turso por fila. */
async function upsertIndicators(rows) {
  if (!rows.length) return 0;
  const CHUNK = 400;
  let total = 0;
  for (let i = 0; i < rows.length; i += CHUNK) {
    const chunk = rows.slice(i, i + CHUNK);
    const statements = chunk.map((r) => ({
      sql: `INSERT INTO threat_indicators (ioc_type, ioc_value, source, confidence, threat_class, malware_family, reference, first_seen, last_seen, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', ?))
            ON CONFLICT(ioc_type, ioc_value, source) DO UPDATE SET
              last_seen = CURRENT_TIMESTAMP,
              expires_at = datetime('now', ?),
              confidence = MAX(confidence, excluded.confidence),
              malware_family = COALESCE(excluded.malware_family, malware_family)`,
      args: [
        r.ioc_type, r.ioc_value, r.source, r.confidence, r.threat_class, r.malware_family, r.reference,
        r.first_seen, r.last_seen, `+${r.ttl_days} days`, `+${r.ttl_days} days`,
      ],
    }));
    await dbLayer.batch(statements);
    total += chunk.length;
  }
  return total;
}

async function recordSourceState(source, { status, error, cursor, rows }) {
  await dbLayer.run(
    `INSERT INTO intel_source_state (source, last_run, last_status, last_error, cursor, rows_upserted)
     VALUES (?, CURRENT_TIMESTAMP, ?, ?, ?, ?)
     ON CONFLICT(source) DO UPDATE SET
       last_run = CURRENT_TIMESTAMP, last_status = excluded.last_status,
       last_error = excluded.last_error, cursor = excluded.cursor, rows_upserted = excluded.rows_upserted`,
    [source, status, error || null, cursor != null ? JSON.stringify(cursor) : null, rows || 0]
  );
}

async function getSourceCursor(source) {
  const row = await dbLayer.get('SELECT cursor FROM intel_source_state WHERE source = ?', [source]);
  if (!row || !row.cursor) return {};
  try { return JSON.parse(row.cursor); } catch { return {}; }
}

async function getSourcesByLastRun() {
  const rows = await dbLayer.all('SELECT source, last_run FROM intel_source_state');
  const byName = new Map(rows.map((r) => [r.source, r.last_run]));
  // Fuentes nunca corridas (last_run null) van primero — es la rotación real.
  return [...SOURCE_ORDER].sort((a, b) => {
    const la = byName.get(a) || '';
    const lb = byName.get(b) || '';
    return la.localeCompare(lb);
  });
}

/**
 * Ingiere todas las fuentes hasta agotar el presupuesto de tiempo o la lista.
 * @param {{deadlineAt: number, otxIndicators?: object[], abuseChAuthKey?: string}} opts
 */
async function ingestAllSources({ deadlineAt, otxIndicators = [], abuseChAuthKey = '' }) {
  const order = await getSourcesByLastRun();
  const result = {};

  for (const source of order) {
    if (Date.now() > deadlineAt) {
      result[source] = { status: 'skipped', reason: 'deadline' };
      continue;
    }
    try {
      let rows = [];
      let cursor = null;

      let skippedIot = 0;
      if (source === 'torexit') rows = await sources.fetchTorExitNodes();
      else if (source === 'feodo') rows = await sources.fetchFeodo();
      else if (source === 'threatfox') rows = await sources.fetchThreatFox({ authKey: abuseChAuthKey, days: 1 });
      else if (source === 'malwarebazaar') rows = await sources.fetchMalwareBazaarRecent({ authKey: abuseChAuthKey });
      else if (source === 'urlhaus') {
        const prev = await getSourceCursor('urlhaus');
        const { rows: urlhausRows, maxId, skippedIot: skipped } = await sources.fetchUrlhausRecent({ sinceId: prev.max_id || 0 });
        rows = urlhausRows;
        cursor = { max_id: maxId };
        skippedIot = skipped || 0;
      } else if (source === 'otx') rows = sources.normalizeOtxIndicators(otxIndicators);

      const upserted = await upsertIndicators(rows);
      await recordSourceState(source, { status: rows.length ? 'ok' : 'ok_empty', cursor, rows: upserted });
      result[source] = { status: 'ok', upserted, ...(source === 'urlhaus' ? { skippedIot } : {}) };
    } catch (err) {
      await recordSourceState(source, { status: 'error', error: err.message });
      result[source] = { status: 'error', error: err.message };
    }
  }
  return result;
}

/** Borra IOCs vencidos y observaciones de red viejas — llamado desde cleanupRetention(). */
async function purgeExpiredIntel() {
  const [expired, staleObs] = await Promise.all([
    dbLayer.run(`DELETE FROM threat_indicators WHERE expires_at < datetime('now', '-1 day')`),
    dbLayer.run(`DELETE FROM endpoint_network_observations WHERE last_seen < datetime('now', '-30 days')`),
  ]);
  return { indicators: expired.rowsAffected || 0, observations: staleObs.rowsAffected || 0 };
}

module.exports = { ingestAllSources, upsertIndicators, purgeExpiredIntel };
