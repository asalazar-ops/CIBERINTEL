// Lookup de indicadores en la ruta caliente de telemetría, y retro-correlación
// diaria. Reemplaza el .find() lineal sobre el blob de otx_cache.indicators
// (deserializado completo en cada POST) por una consulta indexada contra
// threat_indicators, y generaliza la correlación más allá de IPv4/OTX.
const dbLayer = require('../db');
const { isPrivateOrReserved } = require('./sources');

const HASH_RX = { md5: /^[a-f0-9]{32}$/i, sha1: /^[a-f0-9]{40}$/i, sha256: /^[a-f0-9]{64}$/i };

/** {ioc_type, ioc_value} normalizado a partir de un valor crudo, o null si no aplica. */
function normalizeIoc(rawValue, hintType) {
  if (!rawValue || typeof rawValue !== 'string') return null;
  let value = rawValue.trim();
  if (!value) return null;

  if (hintType === 'ipv4' || /^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
    const ip = value.split(':')[0]; // tolera "ip:puerto"
    if (isPrivateOrReserved(ip)) return null;
    return { ioc_type: 'ipv4', ioc_value: ip };
  }
  if (hintType === 'url' || /^https?:\/\//i.test(value)) {
    return { ioc_type: 'url', ioc_value: value.toLowerCase() };
  }
  for (const [type, rx] of Object.entries(HASH_RX)) {
    if (rx.test(value)) return { ioc_type: type, ioc_value: value.toLowerCase() };
  }
  if (hintType === 'domain' || /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value)) {
    return { ioc_type: 'domain', ioc_value: value.toLowerCase() };
  }
  return null;
}

/** Consulta en lote: values ya normalizados (ioc_value). Devuelve Map<ioc_value, row[]>. */
async function lookupIndicators(values) {
  const unique = [...new Set(values.filter(Boolean))];
  const result = new Map();
  if (!unique.length) return result;

  const placeholders = unique.map(() => '?').join(',');
  const rows = await dbLayer.all(
    `SELECT ioc_value, ioc_type, source, confidence, threat_class, malware_family, reference
     FROM threat_indicators
     WHERE ioc_value IN (${placeholders}) AND expires_at > CURRENT_TIMESTAMP`,
    unique
  );
  for (const row of rows) {
    if (!result.has(row.ioc_value)) result.set(row.ioc_value, []);
    result.get(row.ioc_value).push(row);
  }
  return result;
}

// Riesgo por clase de amenaza — reemplaza el +50 fijo de la Fase 1/pre-Fase-3.
// anonymizer (Tor) va deliberadamente bajo: un endpoint hablando con un exit
// node solo significa que alguien abrió Tor Browser, no es en sí malicioso.
const RISK_BY_CLASS = {
  c2: { risk: 60, severity: 'CRITICAL', detectionType: 'THREAT_INTEL_MATCH' },
  botnet_cc: { risk: 60, severity: 'CRITICAL', detectionType: 'THREAT_INTEL_MATCH' },
  payload_delivery: { risk: 45, severity: 'HIGH', detectionType: 'THREAT_INTEL_MATCH' },
  malware_sample: { risk: 45, severity: 'HIGH', detectionType: 'THREAT_INTEL_MATCH' },
  anonymizer: { risk: 15, severity: 'LOW', detectionType: 'ANONYMIZER_CONTACT' },
  generic: { risk: 40, severity: 'MEDIUM', detectionType: 'THREAT_INTEL_MATCH' },
};

/** Varias fuentes coincidiendo en el mismo IOC es señal, no ruido. */
function scoreFromMatches(rows) {
  if (!rows || !rows.length) return null;
  const best = rows.reduce((a, b) => (b.confidence > a.confidence ? b : a));
  const cls = RISK_BY_CLASS[best.threat_class] || RISK_BY_CLASS.generic;
  const sourceCount = new Set(rows.map((r) => r.source)).size;
  const risk = Math.min(100, cls.risk + 10 * (sourceCount - 1));
  return {
    risk, severity: cls.severity, detectionType: cls.detectionType,
    bestSource: best.source, sourceCount, confidence: best.confidence,
    threatClass: best.threat_class, malwareFamily: best.malware_family,
    reference: best.reference,
  };
}

/** Idempotente vía la PK (agent_id, indicator) — devuelve {isNew}. */
async function upsertMatch(agentId, iocValue, iocType, scored, mode = 'live') {
  const res = await dbLayer.run(
    `INSERT INTO threat_intel_matches (agent_id, indicator, ioc_type, match_mode, best_source, source_count, confidence, threat_class, malware_family)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(agent_id, indicator) DO NOTHING`,
    [agentId, iocValue, iocType, mode, scored.bestSource, scored.sourceCount, scored.confidence, scored.threatClass, scored.malwareFamily]
  );
  return { isNew: (res.rowsAffected || 0) > 0 };
}

const OBS_MAX_PER_BATCH = 10;

/** Registra hasta OBS_MAX_PER_BATCH observaciones de red nuevas/refrescadas para un agente. */
async function recordObservations(agentId, observations) {
  const capped = observations.slice(0, OBS_MAX_PER_BATCH);
  for (const obs of capped) {
    // El WHERE en el DO UPDATE convierte el conflicto en no-op si ya se
    // refrescó hace menos de 6h — así un agente charlatán no genera una
    // escritura por cada evento de red, solo unas pocas por día y endpoint.
    await dbLayer.run(
      `INSERT INTO endpoint_network_observations (agent_id, ioc_type, ioc_value, sample_process)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(agent_id, ioc_type, ioc_value) DO UPDATE SET
         last_seen = CURRENT_TIMESTAMP, hit_count = hit_count + 1
       WHERE last_seen < datetime('now', '-6 hours')`,
      [agentId, obs.ioc_type, obs.ioc_value, obs.sample_process || null]
    );
  }
}

/**
 * Pase de retro-correlación: contrasta el histórico de destinos observados
 * (endpoint_network_observations) contra el catálogo de IOCs vigente, para
 * detectar contactos pasados a un indicador añadido DESPUÉS del hecho — algo
 * que el lookup en vivo nunca puede capturar. Excluye 'anonymizer' (Tor no
 * amerita una alerta retroactiva) y trabaja en SQL puro, sin traer filas a
 * Node, para mantenerse dentro del presupuesto del cron.
 */
async function runRetroCorrelation({ limit = 500 } = {}) {
  // OJO: usar datetime('now') de SQLite, no new Date().toISOString() de JS.
  // SQLite CURRENT_TIMESTAMP/datetime('now') produce "YYYY-MM-DD HH:MM:SS"
  // (espacio, sin 'Z'); el ISO de JS produce "YYYY-MM-DDTHH:MM:SS.sssZ". La
  // comparación de abajo es de strings — con formatos distintos, el espacio
  // (0x20) ordena antes que 'T' (0x54) en esa posición, así que CUALQUIER
  // matched_at recién insertado por CURRENT_TIMESTAMP comparaba como "menor"
  // que el startedAt de JS y el filtro nunca encontraba nada (bug real,
  // encontrado al probar: 0 detecciones nuevas siempre, incluso con matches
  // frescos confirmados en la tabla).
  const startedAtRow = await dbLayer.get(`SELECT datetime('now') as now`);
  const startedAt = startedAtRow.now;

  await dbLayer.run(
    `INSERT OR IGNORE INTO threat_intel_matches
       (agent_id, indicator, ioc_type, match_mode, best_source, source_count, confidence, threat_class, malware_family)
     SELECT o.agent_id, o.ioc_value, o.ioc_type, 'retro',
            (SELECT t2.source FROM threat_indicators t2
              WHERE t2.ioc_value = o.ioc_value AND t2.ioc_type = o.ioc_type
              ORDER BY t2.confidence DESC LIMIT 1),
            COUNT(DISTINCT t.source), MAX(t.confidence), MAX(t.threat_class), MAX(t.malware_family)
     FROM endpoint_network_observations o
     JOIN threat_indicators t ON t.ioc_value = o.ioc_value AND t.ioc_type = o.ioc_type
     WHERE t.expires_at > CURRENT_TIMESTAMP AND t.threat_class <> 'anonymizer'
     GROUP BY o.agent_id, o.ioc_value, o.ioc_type
     LIMIT ?`,
    [limit]
  );

  const newMatches = await dbLayer.all(
    `SELECT m.agent_id, m.indicator, m.threat_class, m.confidence, m.best_source, m.malware_family, o.first_seen, o.hit_count
     FROM threat_intel_matches m
     JOIN endpoint_network_observations o ON o.agent_id = m.agent_id AND o.ioc_value = m.indicator AND o.ioc_type = m.ioc_type
     WHERE m.match_mode = 'retro' AND m.matched_at >= ?`,
    [startedAt]
  );

  if (!newMatches.length) return { newDetections: 0, affectedAgents: 0 };

  const statements = newMatches.map((m) => {
    const cls = RISK_BY_CLASS[m.threat_class] || RISK_BY_CLASS.generic;
    const score = Math.min(60, m.confidence || cls.risk);
    return {
      sql: `INSERT INTO sensor_detections (agent_id, detection_type, severity, score, details, behavior_chain)
            VALUES (?, 'THREAT_INTEL_RETRO', ?, ?, ?, ?)`,
      args: [
        m.agent_id, cls.severity, score,
        `Retro-correlación: ${m.indicator} (${m.best_source}, ${m.malware_family || 'n/d'}) contactado el ${m.first_seen}`,
        JSON.stringify({ ioc: m.indicator, first_seen: m.first_seen, hits: m.hit_count }),
      ],
    };
  });
  await dbLayer.batch(statements);

  const totalByAgent = new Map();
  for (const m of newMatches) {
    const cls = RISK_BY_CLASS[m.threat_class] || RISK_BY_CLASS.generic;
    const score = Math.min(60, m.confidence || cls.risk);
    totalByAgent.set(m.agent_id, (totalByAgent.get(m.agent_id) || 0) + score);
  }

  return { newDetections: newMatches.length, affectedAgents: totalByAgent, byAgentScore: totalByAgent };
}

module.exports = {
  normalizeIoc, lookupIndicators, scoreFromMatches, upsertMatch,
  recordObservations, runRetroCorrelation, RISK_BY_CLASS, OBS_MAX_PER_BATCH,
};
