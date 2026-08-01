// Migración única: data.json + assets.json + sensors.db (sqlite3 local) -> Turso.
// Uso:  node server/migrate_to_turso.js
//
// Idempotente en articles/assets (unique_id / domain son UNIQUE) y en las tablas
// de sensores (agent_id es PRIMARY KEY, finding_url es UNIQUE): correr el script
// dos veces no duplica filas, solo re-inserta lo que falte.
//
// Único lugar del proyecto que aún depende de `sqlite3` (módulo nativo): lee el
// sensors.db legado de una instalación local previa a esta migración. server.js
// ya no lo usa — ver server/db.js. Mantener sqlite3 en dependencies solo por
// este script; si no hay sensors.db que migrar, es una dependencia opcional.
// Script standalone: server.js normalmente carga dotenv antes de requerir
// server/db.js, pero corriendo este archivo directamente nadie más lo hace —
// sin esto, TURSO_DATABASE_URL nunca llega y el script migra en silencio hacia
// el archivo local embebido en vez de la base remota real.
require('dotenv').config();

const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const db = require('./db');

const ROOT = path.join(__dirname, '..');
const DATA_FILE = path.join(ROOT, 'data.json');
const ASSETS_FILE = path.join(ROOT, 'assets.json');
const SENSORS_DB_FILE = path.join(ROOT, 'sensors.db');

function readJson(file) {
  if (!fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, 'utf-8'));
}

async function migrateArticles() {
  const articles = readJson(DATA_FILE);
  if (!articles) {
    console.log('[articles] data.json no existe, se omite.');
    return { source: 0, inserted: 0 };
  }
  let inserted = 0;
  for (const a of articles) {
    const res = await db.run(
      `INSERT INTO articles (id, unique_id, feed_id, source, category, color, region, sector, actor, severity, title, summary, link, tags, date)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(unique_id) DO NOTHING`,
      [
        a.id, a.uniqueId, a.feedId || null, a.source || null, a.category || null, a.color || null,
        a.region || null, a.sector || null, a.actor || null, a.severity || null,
        a.title || null, a.summary || null, a.link || null,
        JSON.stringify(a.tags || []), a.date || null,
      ]
    );
    if (res.rowsAffected > 0) inserted++;
  }
  return { source: articles.length, inserted };
}

async function migrateAssets() {
  const assets = readJson(ASSETS_FILE);
  if (!assets) {
    console.log('[assets] assets.json no existe, se omite.');
    return { source: 0, inserted: 0 };
  }
  let inserted = 0;
  for (const a of assets) {
    const res = await db.run(
      `INSERT INTO assets (id, domain, spf, dmarc, subdomains, impersonations, risk_score, last_scan, fb_scraper_cache)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(domain) DO NOTHING`,
      [
        a.id, a.domain,
        JSON.stringify(a.spf || {}), JSON.stringify(a.dmarc || {}),
        JSON.stringify(a.subdomains || []), JSON.stringify(a.impersonations || []),
        a.riskScore || 0, a.lastScan || null,
        a.fbScraperCache ? JSON.stringify(a.fbScraperCache) : null,
      ]
    );
    if (res.rowsAffected > 0) inserted++;
  }
  return { source: assets.length, inserted };
}

function openLegacySqlite() {
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(SENSORS_DB_FILE)) return resolve(null);
    const legacy = new sqlite3.Database(SENSORS_DB_FILE, sqlite3.OPEN_READONLY, (err) => {
      if (err) reject(err); else resolve(legacy);
    });
  });
}

function legacyAll(legacyDb, sql) {
  return new Promise((resolve, reject) => {
    legacyDb.all(sql, (err, rows) => (err ? reject(err) : resolve(rows)));
  });
}

async function migrateSensorTable(legacyDb, table, columns, conflictCol) {
  const rows = await legacyAll(legacyDb, `SELECT * FROM ${table}`);
  let inserted = 0;
  const placeholders = columns.map(() => '?').join(', ');
  const conflictClause = conflictCol ? `ON CONFLICT(${conflictCol}) DO NOTHING` : '';
  for (const row of rows) {
    const res = await db.run(
      `INSERT INTO ${table} (${columns.join(', ')}) VALUES (${placeholders}) ${conflictClause}`,
      columns.map((c) => (row[c] === undefined ? null : row[c]))
    );
    if (res.rowsAffected > 0) inserted++;
  }
  return { source: rows.length, inserted };
}

async function migrateSensorsDb() {
  const legacyDb = await openLegacySqlite();
  if (!legacyDb) {
    console.log('[sensors] sensors.db no existe, se omite.');
    return {};
  }

  const results = {};
  results.sensor_endpoints = await migrateSensorTable(
    legacyDb, 'sensor_endpoints',
    ['agent_id', 'hostname', 'ip', 'status', 'last_seen', 'hardware_info', 'software_info'],
    'agent_id'
  );
  results.sensor_telemetry = await migrateSensorTable(
    legacyDb, 'sensor_telemetry',
    ['id', 'agent_id', 'timestamp', 'event_type', 'process_name', 'parent_process', 'target_path',
     'dst_ip', 'dst_domain', 'risk_score', 'mitre_id', 'mitre_tactic', 'mitre_technique', 'severity', 'raw_json'],
    'id'
  );
  results.sensor_detections = await migrateSensorTable(
    legacyDb, 'sensor_detections',
    ['id', 'agent_id', 'timestamp', 'detection_type', 'severity', 'score', 'details', 'behavior_chain'],
    'id'
  );
  results.sensor_behavior_scores = await migrateSensorTable(
    legacyDb, 'sensor_behavior_scores',
    ['agent_id', 'current_score', 'last_alert_timestamp', 'last_update', 'status'],
    'agent_id'
  );
  results.sensor_alerts = await migrateSensorTable(
    legacyDb, 'sensor_alerts',
    ['id', 'agent_id', 'hostname', 'ip', 'event', 'severity', 'timestamp'],
    'id'
  );
  results.brand_protection_findings = await migrateSensorTable(
    legacyDb, 'brand_protection_findings',
    ['id', 'domain', 'finding_url', 'title', 'description', 'source', 'severity', 'detected_at', 'is_new'],
    'finding_url'
  );

  legacyDb.close();
  return results;
}

async function verifyCounts(articlesResult, assetsResult, sensorsResults) {
  console.log('\n── Verificación: recuento origen vs. destino ──');
  let allOk = true;

  const check = async (label, sourceCount, table) => {
    const row = await db.get(`SELECT COUNT(*) as c FROM ${table}`);
    const destCount = row.c;
    // El destino puede ser >= origen si el script ya corrió antes y algo más se
    // agregó desde entonces; lo que no debe pasar nunca es destino < origen.
    const ok = destCount >= sourceCount;
    if (!ok) allOk = false;
    console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label.padEnd(28)} origen=${sourceCount}  destino=${destCount}`);
  };

  await check('articles', articlesResult.source, 'articles');
  await check('assets', assetsResult.source, 'assets');
  for (const [table, r] of Object.entries(sensorsResults)) {
    if (r.source !== undefined) await check(table, r.source, table);
  }

  return allOk;
}

(async () => {
  console.log('Iniciando migración hacia Turso/libSQL...\n');
  await db.initSchema();

  const articlesResult = await migrateArticles();
  console.log(`[articles] origen=${articlesResult.source} insertados=${articlesResult.inserted}`);

  const assetsResult = await migrateAssets();
  console.log(`[assets] origen=${assetsResult.source} insertados=${assetsResult.inserted}`);

  const sensorsResults = await migrateSensorsDb();
  for (const [table, r] of Object.entries(sensorsResults)) {
    console.log(`[${table}] origen=${r.source} insertados=${r.inserted}`);
  }

  const ok = await verifyCounts(articlesResult, assetsResult, sensorsResults);
  console.log(ok ? '\n✅ Migración verificada: todos los recuentos coinciden.' : '\n❌ Discrepancia de recuentos — revisar antes de continuar.');
  process.exit(ok ? 0 : 1);
})().catch((err) => {
  console.error('Error durante la migración:', err);
  process.exit(1);
});
