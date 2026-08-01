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
  await run(`CREATE TABLE IF NOT EXISTS sensor_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT,
    hostname TEXT,
    ip TEXT,
    event TEXT,
    severity TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  await run(`CREATE TABLE IF NOT EXISTS sensor_endpoints (
    agent_id TEXT PRIMARY KEY,
    hostname TEXT,
    ip TEXT,
    status TEXT,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    hardware_info TEXT,
    software_info TEXT
  )`);

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
