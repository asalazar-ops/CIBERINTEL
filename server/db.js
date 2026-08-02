// Capa de datos sobre Turso (libSQL). Reemplaza sqlite3 (módulo nativo, no
// funciona en serverless) y los archivos data.json/assets.json (disco no
// persistente en Vercel). Habla el mismo dialecto SQLite que el server.js
// original, así que el SQL de scoring de comportamiento (julianday, ON
// CONFLICT...excluded) portó sin reescribir.
//
// TURSO_DATABASE_URL vacío => arranca embebido contra un archivo local
// (server/local.db), útil para desarrollo sin depender de la nube. En
// producción, ambas variables son obligatorias.
const path = require('path');
const { createClient } = require('@libsql/client');

const TURSO_URL = process.env.TURSO_DATABASE_URL || '';
const TURSO_TOKEN = process.env.TURSO_AUTH_TOKEN || '';

if (!TURSO_URL) {
  console.warn('\n⚠️  TURSO_DATABASE_URL no está definido — usando base local embebida (server/local.db).');
  console.warn('   Esto NO persiste en Vercel: configura Turso antes de desplegar.\n');
}

const client = createClient(
  TURSO_URL
    ? { url: TURSO_URL, authToken: TURSO_TOKEN }
    : { url: `file:${path.join(__dirname, 'local.db')}` }
);

/** Ejecuta una sentencia sin retorno de filas. args es un array posicional (?). */
async function run(sql, args = []) {
  return client.execute({ sql, args });
}

/** Devuelve la primera fila o undefined, igual que sqlite3 db.get(). */
async function get(sql, args = []) {
  const res = await client.execute({ sql, args });
  return res.rows[0];
}

/** Devuelve todas las filas como array de objetos planos, igual que sqlite3 db.all(). */
async function all(sql, args = []) {
  const res = await client.execute({ sql, args });
  return res.rows.map((r) => ({ ...r }));
}

/** Varias sentencias en una transacción (usado por la migración de datos). */
async function batch(statements) {
  return client.batch(statements, 'write');
}

async function initSchema() {
  await run(`CREATE TABLE IF NOT EXISTS sensor_endpoints (
    agent_id TEXT PRIMARY KEY,
    hostname TEXT,
    ip TEXT,
    status TEXT,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    hardware_info TEXT,
    software_info TEXT
  )`);
  // Columnas de la Fase 4 (vulnerabilidades). ALTER guardado porque SQLite/
  // libSQL no soporta "ADD COLUMN IF NOT EXISTS": falla con "duplicate column
  // name" en cualquier despliegue que ya las tenga, y eso es el caso normal
  // tras el primer arranque.
  for (const alter of [
    `ALTER TABLE sensor_endpoints ADD COLUMN sw_hash TEXT`,
    `ALTER TABLE sensor_endpoints ADD COLUMN vuln_state TEXT DEFAULT 'pending'`,
    `ALTER TABLE sensor_endpoints ADD COLUMN last_correlated DATETIME`,
    `ALTER TABLE sensor_endpoints ADD COLUMN os_build TEXT`,
    `ALTER TABLE sensor_endpoints ADD COLUMN hotfixes TEXT`,
  ]) {
    try { await run(alter); } catch (e) { if (!/duplicate column/i.test(e.message)) throw e; }
  }

  await run(`CREATE TABLE IF NOT EXISTS sensor_telemetry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT,
    process_name TEXT,
    parent_process TEXT,
    target_path TEXT,
    dst_ip TEXT,
    dst_domain TEXT,
    risk_score INTEGER DEFAULT 0,
    mitre_id TEXT,
    mitre_tactic TEXT,
    mitre_technique TEXT,
    severity TEXT,
    raw_json TEXT
  )`);
  // Sin estos índices, cada lectura del EDR (behavior, analysis/summary,
  // retención) era un full scan: las tablas de telemetría/detecciones crecen
  // sin límite superior de tamaño y se consultan por agent_id/timestamp en
  // casi todas las rutas.
  await run(`CREATE INDEX IF NOT EXISTS idx_telemetry_agent ON sensor_telemetry(agent_id, timestamp)`);
  await run(`CREATE INDEX IF NOT EXISTS idx_telemetry_ts ON sensor_telemetry(timestamp)`);

  await run(`CREATE TABLE IF NOT EXISTS sensor_detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    detection_type TEXT,
    severity TEXT,
    score INTEGER,
    details TEXT,
    behavior_chain TEXT
  )`);
  await run(`CREATE INDEX IF NOT EXISTS idx_detections_agent ON sensor_detections(agent_id, timestamp)`);

  await run(`CREATE TABLE IF NOT EXISTS sensor_behavior_scores (
    agent_id TEXT PRIMARY KEY,
    current_score INTEGER DEFAULT 0,
    last_alert_timestamp DATETIME,
    last_update DATETIME,
    status TEXT DEFAULT 'low'
  )`);

  await run(`CREATE TABLE IF NOT EXISTS brand_protection_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT,
    finding_url TEXT UNIQUE,
    title TEXT,
    description TEXT,
    source TEXT,
    severity TEXT,
    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_new INTEGER DEFAULT 1
  )`);

  // Ledger de coincidencias de threat intel por endpoint. La PK da idempotencia:
  // sin esto, cada lote de telemetría con la misma IP maliciosa insertaba una
  // fila nueva en sensor_detections y sumaba +50 al behavior score otra vez —
  // un beacon cada 30s saturaba el score en minutos. Vive fuera del bloque de
  // Fase 3 (motor de inteligencia multi-fuente) porque corrige un bug ya
  // presente en la correlación OTX actual.
  await run(`CREATE TABLE IF NOT EXISTS threat_intel_matches (
    agent_id TEXT NOT NULL,
    indicator TEXT NOT NULL,
    matched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    detection_id INTEGER,
    PRIMARY KEY (agent_id, indicator)
  )`);
  // Columnas añadidas en la Fase 3: el motor multi-fuente necesita saber qué
  // fuente/clase/familia disparó el match para escalar el riesgo (c2 +60,
  // payload_delivery +45, anonymizer +15 — ver server/intel/lookup.js) y para
  // distinguir coincidencias en vivo (match_mode='live') de las encontradas
  // por el pase de retro-correlación diario (match_mode='retro'). SQLite/libSQL
  // no soporta "ADD COLUMN IF NOT EXISTS", así que cada ALTER va envuelto en
  // try/catch: falla con "duplicate column name" en despliegues que ya la
  // tienen, y eso es exactamente el caso normal tras el primer arranque.
  for (const alter of [
    `ALTER TABLE threat_intel_matches ADD COLUMN ioc_type TEXT`,
    `ALTER TABLE threat_intel_matches ADD COLUMN match_mode TEXT DEFAULT 'live'`,
    `ALTER TABLE threat_intel_matches ADD COLUMN best_source TEXT`,
    `ALTER TABLE threat_intel_matches ADD COLUMN source_count INTEGER DEFAULT 1`,
    `ALTER TABLE threat_intel_matches ADD COLUMN confidence INTEGER`,
    `ALTER TABLE threat_intel_matches ADD COLUMN threat_class TEXT`,
    `ALTER TABLE threat_intel_matches ADD COLUMN malware_family TEXT`,
  ]) {
    try { await run(alter); } catch (e) { if (!/duplicate column/i.test(e.message)) throw e; }
  }

  // ── Motor de inteligencia multi-fuente (Fase 3) ──
  // Reemplaza la ruta de lectura de otx_cache.indicators en el hot path de
  // telemetría (un .find() lineal sobre un blob JSON deserializado en cada
  // POST) por una tabla indexada que además agrega ThreatFox, URLhaus,
  // MalwareBazaar, Feodo Tracker y Tor exit nodes — antes solo se correlacionaba
  // IPv4 de OTX. otx_cache se conserva (los paneles de pulses/adversaries/
  // industries siguen viviendo de ahí); lo que cambia es que OTX pasa a ser
  // un productor más hacia esta tabla, no la única fuente del lookup.
  await run(`CREATE TABLE IF NOT EXISTS threat_indicators (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type       TEXT NOT NULL,
    ioc_value      TEXT NOT NULL,
    source         TEXT NOT NULL,
    confidence     INTEGER NOT NULL DEFAULT 50,
    threat_class   TEXT,
    malware_family TEXT,
    reference      TEXT,
    first_seen     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at     DATETIME NOT NULL,
    UNIQUE (ioc_type, ioc_value, source)
  )`);
  // Índice crítico del hot path: el lookup filtra por valor sin conocer el
  // tipo de antemano (el evento trae dst_ip/file_hash, no "esto es IPv4").
  // El índice de la UNIQUE de arriba no sirve para eso — su primera columna
  // es ioc_type, así que un WHERE ioc_value IN (...) no lo usaría.
  await run(`CREATE INDEX IF NOT EXISTS idx_ti_value ON threat_indicators(ioc_value, ioc_type)`);
  await run(`CREATE INDEX IF NOT EXISTS idx_ti_expires ON threat_indicators(expires_at)`);
  await run(`CREATE INDEX IF NOT EXISTS idx_ti_source ON threat_indicators(source, last_seen)`);

  // Estado por fuente: cursores incrementales (ej. el id máximo ya ingerido de
  // URLhaus) y último resultado — permite reanudar donde se quedó una fuente
  // que no alcanzó a terminar en la ventana de 60s del cron, sin repetir
  // trabajo ni perder progreso entre corridas diarias.
  await run(`CREATE TABLE IF NOT EXISTS intel_source_state (
    source        TEXT PRIMARY KEY,
    last_run      DATETIME,
    last_status   TEXT,
    last_error    TEXT,
    cursor        TEXT,
    rows_upserted INTEGER DEFAULT 0
  )`);

  // Conjunto ACOTADO de destinos distintos vistos por endpoint — NO es un log
  // de eventos (la PK colapsa repeticiones). Es lo que hace posible la
  // retro-correlación sin persistir toda la telemetría de red con risk_score=0
  // (que hoy se descarta: ver el filtro >=30 en POST /api/sensors/telemetry).
  await run(`CREATE TABLE IF NOT EXISTS endpoint_network_observations (
    agent_id       TEXT NOT NULL,
    ioc_type       TEXT NOT NULL,
    ioc_value      TEXT NOT NULL,
    first_seen     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    hit_count      INTEGER NOT NULL DEFAULT 1,
    sample_process TEXT,
    PRIMARY KEY (agent_id, ioc_type, ioc_value)
  )`);
  await run(`CREATE INDEX IF NOT EXISTS idx_eno_value ON endpoint_network_observations(ioc_value, ioc_type)`);
  await run(`CREATE INDEX IF NOT EXISTS idx_eno_lastseen ON endpoint_network_observations(last_seen)`);

  // ── Vulnerabilidades sobre inventario (Fase 4) ──
  // NVD por cpeName produce ~99% de falsos positivos (verificado en el plan:
  // un CPE "runs-on" marcado vulnerable:false igual aparece en los resultados).
  // Enfoque elegido: diccionario curado de productos comunes -> CPE 2.3,
  // editable en runtime sin redesplegar, más comparación de versiones local
  // anclada en KEV. match_kind 'exact' matchea el DisplayName normalizado tal
  // cual; 'prefix' matchea el inicio (ej. "Google Chrome" antes de la versión
  // que a veces viene pegada al nombre).
  await run(`CREATE TABLE IF NOT EXISTS cpe_dictionary (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    match_kind      TEXT NOT NULL,
    match_value     TEXT NOT NULL,
    publisher_hint  TEXT,
    cpe_part        TEXT NOT NULL DEFAULT 'a',
    cpe_vendor      TEXT NOT NULL,
    cpe_product     TEXT NOT NULL,
    version_source  TEXT DEFAULT 'display',
    version_regex   TEXT,
    confidence      TEXT DEFAULT 'high',
    enabled         INTEGER DEFAULT 1,
    notes           TEXT,
    UNIQUE (match_kind, match_value, publisher_hint)
  )`);
  await run(`CREATE INDEX IF NOT EXISTS idx_cpedict_value ON cpe_dictionary(match_value)`);

  // Catálogo de CVEs — SOLO los que tocan un producto del diccionario (no un
  // espejo completo de NVD, que son millones de filas irrelevantes).
  await run(`CREATE TABLE IF NOT EXISTS cve_catalog (
    cve_id          TEXT PRIMARY KEY,
    published       DATETIME,
    last_modified   DATETIME,
    cvss_score      REAL,
    cvss_severity   TEXT,
    cvss_vector     TEXT,
    description     TEXT,
    in_kev          INTEGER NOT NULL DEFAULT 0,
    kev_date_added  DATE,
    kev_due_date    DATE,
    kev_ransomware  TEXT,
    epss_score      REAL,
    epss_percentile REAL,
    epss_updated    DATE,
    refreshed_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  await run(`CREATE INDEX IF NOT EXISTS idx_cve_prio ON cve_catalog(in_kev DESC, epss_score DESC)`);

  // Rangos vulnerables — una fila por cpeMatch con vulnerable:true de NVD.
  // Sin cota de versión el CVE se descarta al sincronizar (no se reporta
  // "afecta a todas las versiones" — ver server/vuln/catalog.js).
  await run(`CREATE TABLE IF NOT EXISTS cve_affected_ranges (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id                   TEXT NOT NULL,
    cpe_vendor               TEXT NOT NULL,
    cpe_product              TEXT NOT NULL,
    version_exact            TEXT,
    version_start_including  TEXT,
    version_start_excluding  TEXT,
    version_end_including    TEXT,
    version_end_excluding    TEXT,
    UNIQUE (cve_id, cpe_vendor, cpe_product, version_exact,
            version_start_including, version_start_excluding,
            version_end_including, version_end_excluding)
  )`);
  // Índice crítico: la correlación consulta por producto, no por CVE.
  await run(`CREATE INDEX IF NOT EXISTS idx_car_product ON cve_affected_ranges(cpe_vendor, cpe_product)`);

  // Hallazgos por endpoint — matched_rule guarda la comparación legible
  // ("< 120.0.6099.129") para que el hallazgo sea auditable a mano.
  await run(`CREATE TABLE IF NOT EXISTS endpoint_vulnerabilities (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id         TEXT NOT NULL,
    cve_id           TEXT NOT NULL,
    product_name     TEXT NOT NULL,
    product_version  TEXT NOT NULL,
    cpe_vendor       TEXT,
    cpe_product      TEXT,
    match_confidence TEXT,
    matched_rule     TEXT,
    first_detected   DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_confirmed   DATETIME DEFAULT CURRENT_TIMESTAMP,
    status           TEXT DEFAULT 'open',
    UNIQUE (agent_id, cve_id, cpe_product, product_version)
  )`);
  await run(`CREATE INDEX IF NOT EXISTS idx_epv_agent ON endpoint_vulnerabilities(agent_id, status)`);
  await run(`CREATE INDEX IF NOT EXISTS idx_epv_cve ON endpoint_vulnerabilities(cve_id)`);

  // Honestidad del módulo: lo que NO se evaluó no debe leerse como "sin
  // vulnerabilidades" — se cuenta y se muestra aparte en la UI.
  await run(`CREATE TABLE IF NOT EXISTS unmapped_software (
    name_normalized  TEXT PRIMARY KEY,
    sample_name      TEXT,
    sample_publisher TEXT,
    sample_version   TEXT,
    endpoint_count   INTEGER DEFAULT 1,
    reason           TEXT,
    last_seen        DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // ── Reemplazan data.json y assets.json ──
  // uniqueId UNIQUE reemplaza el localData.some(d => d.uniqueId === uniqueId)
  // O(n²) que hacía server.js en cada artículo de cada feed procesado.
  await run(`CREATE TABLE IF NOT EXISTS articles (
    id TEXT PRIMARY KEY,
    unique_id TEXT UNIQUE NOT NULL,
    feed_id TEXT,
    source TEXT,
    category TEXT,
    color TEXT,
    region TEXT,
    sector TEXT,
    actor TEXT,
    severity TEXT,
    title TEXT,
    summary TEXT,
    link TEXT,
    tags TEXT,   -- JSON array
    date DATETIME
  )`);
  await run(`CREATE INDEX IF NOT EXISTS idx_articles_date ON articles(date)`);
  await run(`CREATE INDEX IF NOT EXISTS idx_articles_feed ON articles(feed_id)`);

  // spf/dmarc/subdomains/impersonations/fbScraperCache se guardan como JSON:
  // son blobs de forma variable que el resto del código ya trata como objetos
  // opacos (los arma scanDomain y los consume el frontend tal cual).
  await run(`CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    domain TEXT UNIQUE NOT NULL,
    spf TEXT,
    dmarc TEXT,
    subdomains TEXT,
    impersonations TEXT,
    risk_score INTEGER DEFAULT 0,
    last_scan DATETIME,
    fb_scraper_cache TEXT
  )`);

  // Reemplaza el objeto `otxCache` en memoria (server/app.js original): en
  // serverless cada invocación es un proceso nuevo, así que el caché en RAM se
  // pierde entre peticiones y el TTL de 15 min nunca se cumplía de verdad.
  // single_row_id fuerza una única fila (patrón "tabla singleton").
  await run(`CREATE TABLE IF NOT EXISTS otx_cache (
    single_row_id INTEGER PRIMARY KEY CHECK (single_row_id = 1),
    pulses TEXT,
    indicators TEXT,
    last_fetch DATETIME
  )`);

  // Estado observable de cada cron: sin logs persistentes de Vercel a mano,
  // esta tabla es la única forma de saber desde el propio dashboard si
  // /api/cron/* corrió, cuándo, y si falló.
  await run(`CREATE TABLE IF NOT EXISTS cron_runs (
    job_name TEXT PRIMARY KEY,
    last_run DATETIME,
    last_status TEXT,
    last_detail TEXT
  )`);
}

// ── Shim de compatibilidad con la API callback-style de sqlite3 ──
// server.js original fue escrito contra db.run(sql, params, cb), db.get(...),
// db.all(...) y db.prepare(sql).run(params)...finalize(). Reproducir esa misma
// forma aquí evita reescribir cada uno de los ~30 call sites de las rutas EDR
// (heartbeat, telemetry, behavior, analysis/summary...) — solo cambia el
// `require('sqlite3')` por `require('./db')`. El motor por debajo es libSQL:
// asíncrono de verdad, pero la superficie que ve el código de arriba es igual.
//
// Particularidad de sqlite3 que este shim replica: dentro del callback de
// run(), `this.lastID` da el rowid insertado — server.js lo usa en
// /api/sensors/report (`res.json({ alertId: this.lastID })`).
const legacy = {
  run(sql, paramsOrCb, maybeCb) {
    const hasParams = Array.isArray(paramsOrCb);
    const params = hasParams ? paramsOrCb : [];
    const cb = hasParams ? maybeCb : paramsOrCb;

    client.execute({ sql, args: params })
      .then((res) => {
        if (typeof cb === 'function') {
          const ctx = { lastID: Number(res.lastInsertRowid ?? 0), changes: res.rowsAffected };
          cb.call(ctx, null);
        }
      })
      .catch((err) => { if (typeof cb === 'function') cb.call({}, err); });
  },

  get(sql, paramsOrCb, maybeCb) {
    const hasParams = Array.isArray(paramsOrCb);
    const params = hasParams ? paramsOrCb : [];
    const cb = hasParams ? maybeCb : paramsOrCb;

    client.execute({ sql, args: params })
      .then((res) => { if (typeof cb === 'function') cb(null, res.rows[0] ? { ...res.rows[0] } : undefined); })
      .catch((err) => { if (typeof cb === 'function') cb(err); });
  },

  all(sql, paramsOrCb, maybeCb) {
    const hasParams = Array.isArray(paramsOrCb);
    const params = hasParams ? paramsOrCb : [];
    const cb = hasParams ? maybeCb : paramsOrCb;

    client.execute({ sql, args: params })
      .then((res) => { if (typeof cb === 'function') cb(null, res.rows.map((r) => ({ ...r }))); })
      .catch((err) => { if (typeof cb === 'function') cb(err); });
  },

  // sqlite3 db.prepare() es síncrono y devuelve un statement reusable; aquí
  // basta con acumular los batches y ejecutarlos en finalize(), que es el
  // único punto donde server.js necesita que ya hayan corrido (antes de
  // calcular el score agregado del lote de telemetría).
  prepare(sql) {
    const pending = [];
    return {
      run(params) {
        pending.push(client.execute({ sql, args: params }).catch((err) => {
          console.error('[DB] Error en statement preparado:', err.message);
        }));
        return this;
      },
      finalize(cb) {
        Promise.all(pending).then(() => { if (typeof cb === 'function') cb(null); });
      },
    };
  },
};

module.exports = { client, run, get, all, batch, initSchema, legacy };
