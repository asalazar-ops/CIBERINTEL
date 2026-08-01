// Reemplaza los arrays en memoria `localData`/`localAssets` (cargados de
// data.json/assets.json y regrabados enteros en cada mutación) por consultas
// directas a Turso. Necesario para serverless: dos invocaciones concurrentes no
// pueden compartir un array en RAM, y el disco no persiste entre invocaciones.
//
// spf/dmarc/subdomains/impersonations/fbScraperCache/tags viajaban como objetos
// JS anidados; aquí se (de)serializan a JSON en las columnas TEXT correspondientes,
// para que el resto del código (scanDomain, el frontend) siga viéndolos igual.
const dbLayer = require('./db');

function rowToArticle(row) {
  return {
    id: row.id,
    uniqueId: row.unique_id,
    feedId: row.feed_id,
    source: row.source,
    category: row.category,
    color: row.color,
    region: row.region,
    sector: row.sector,
    actor: row.actor,
    severity: row.severity,
    title: row.title,
    summary: row.summary,
    link: row.link,
    tags: row.tags ? JSON.parse(row.tags) : [],
    date: row.date,
  };
}

function rowToAsset(row) {
  return {
    id: row.id,
    domain: row.domain,
    spf: row.spf ? JSON.parse(row.spf) : { status: 'missing', record: null },
    dmarc: row.dmarc ? JSON.parse(row.dmarc) : { status: 'missing', record: null },
    subdomains: row.subdomains ? JSON.parse(row.subdomains) : [],
    impersonations: row.impersonations ? JSON.parse(row.impersonations) : [],
    riskScore: row.risk_score || 0,
    lastScan: row.last_scan,
    fbScraperCache: row.fb_scraper_cache ? JSON.parse(row.fb_scraper_cache) : undefined,
  };
}

// ── Artículos (reemplaza data.json) ──
const articles = {
  async count() {
    const row = await dbLayer.get('SELECT COUNT(*) as c FROM articles');
    return row.c;
  },

  async existsByUniqueId(uniqueId) {
    const row = await dbLayer.get('SELECT 1 FROM articles WHERE unique_id = ?', [uniqueId]);
    return !!row;
  },

  async insert(article) {
    await dbLayer.run(
      `INSERT INTO articles (id, unique_id, feed_id, source, category, color, region, sector, actor, severity, title, summary, link, tags, date)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        article.id, article.uniqueId, article.feedId, article.source, article.category, article.color,
        article.region, article.sector, article.actor, article.severity,
        article.title, article.summary, article.link, JSON.stringify(article.tags || []), article.date,
      ]
    );
  },

  /** Todos los artículos, más recientes primero (igual orden que usaba el sort() original). */
  async listAll() {
    const rows = await dbLayer.all('SELECT * FROM articles ORDER BY date DESC');
    return rows.map(rowToArticle);
  },

  async deleteAll() {
    await dbLayer.run('DELETE FROM articles');
  },

  async deleteOlderThan(cutoffIso) {
    await dbLayer.run('DELETE FROM articles WHERE date < ?', [cutoffIso]);
  },

  async deleteByFeedId(feedId) {
    await dbLayer.run('DELETE FROM articles WHERE feed_id = ?', [feedId]);
  },
};

// ── Assets (reemplaza assets.json) ──
const assets = {
  async listAll() {
    const rows = await dbLayer.all('SELECT * FROM assets ORDER BY domain');
    return rows.map(rowToAsset);
  },

  async findById(id) {
    const row = await dbLayer.get('SELECT * FROM assets WHERE id = ?', [id]);
    return row ? rowToAsset(row) : null;
  },

  async findByDomain(domain) {
    const row = await dbLayer.get('SELECT * FROM assets WHERE domain = ?', [domain]);
    return row ? rowToAsset(row) : null;
  },

  async existsByDomain(domain) {
    const row = await dbLayer.get('SELECT 1 FROM assets WHERE lower(domain) = lower(?)', [domain]);
    return !!row;
  },

  async insert(asset) {
    await dbLayer.run(
      `INSERT INTO assets (id, domain, spf, dmarc, subdomains, impersonations, risk_score, last_scan, fb_scraper_cache)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        asset.id, asset.domain,
        JSON.stringify(asset.spf || {}), JSON.stringify(asset.dmarc || {}),
        JSON.stringify(asset.subdomains || []), JSON.stringify(asset.impersonations || []),
        asset.riskScore || 0, asset.lastScan || null,
        asset.fbScraperCache ? JSON.stringify(asset.fbScraperCache) : null,
      ]
    );
  },

  /** Sobrescribe los campos de escaneo de un asset (equivalente a Object.assign(asset, scanResult) + saveAssets()). */
  async updateScanResult(id, scanResult) {
    await dbLayer.run(
      `UPDATE assets SET spf = ?, dmarc = ?, subdomains = ?, impersonations = ?, risk_score = ?, last_scan = ? WHERE id = ?`,
      [
        JSON.stringify(scanResult.spf || {}), JSON.stringify(scanResult.dmarc || {}),
        JSON.stringify(scanResult.subdomains || []), JSON.stringify(scanResult.impersonations || []),
        scanResult.riskScore || 0, scanResult.lastScan || null, id,
      ]
    );
  },

  async updateFbScraperCache(id, fbScraperCache) {
    await dbLayer.run('UPDATE assets SET fb_scraper_cache = ? WHERE id = ?', [JSON.stringify(fbScraperCache), id]);
  },

  async deleteById(id) {
    const res = await dbLayer.run('DELETE FROM assets WHERE id = ?', [id]);
    return res.rowsAffected > 0;
  },
};

// ── Caché OTX (reemplaza el objeto `otxCache` en memoria) ──
const otxCache = {
  async read() {
    const row = await dbLayer.get('SELECT * FROM otx_cache WHERE single_row_id = 1');
    if (!row) return { pulses: [], indicators: [], lastFetch: 0 };
    return {
      pulses: row.pulses ? JSON.parse(row.pulses) : [],
      indicators: row.indicators ? JSON.parse(row.indicators) : [],
      lastFetch: row.last_fetch ? new Date(row.last_fetch + 'Z').getTime() : 0,
    };
  },

  async write({ pulses, indicators }) {
    await dbLayer.run(
      `INSERT INTO otx_cache (single_row_id, pulses, indicators, last_fetch)
       VALUES (1, ?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(single_row_id) DO UPDATE SET
         pulses = excluded.pulses, indicators = excluded.indicators, last_fetch = CURRENT_TIMESTAMP`,
      [JSON.stringify(pulses), JSON.stringify(indicators)]
    );
  },
};

// ── Estado de cron jobs (observabilidad sin acceso a logs de Vercel) ──
const cronRuns = {
  async recordSuccess(jobName, detail) {
    await dbLayer.run(
      `INSERT INTO cron_runs (job_name, last_run, last_status, last_detail) VALUES (?, CURRENT_TIMESTAMP, 'ok', ?)
       ON CONFLICT(job_name) DO UPDATE SET last_run = CURRENT_TIMESTAMP, last_status = 'ok', last_detail = excluded.last_detail`,
      [jobName, detail || null]
    );
  },

  async recordFailure(jobName, errorMessage) {
    await dbLayer.run(
      `INSERT INTO cron_runs (job_name, last_run, last_status, last_detail) VALUES (?, CURRENT_TIMESTAMP, 'error', ?)
       ON CONFLICT(job_name) DO UPDATE SET last_run = CURRENT_TIMESTAMP, last_status = 'error', last_detail = excluded.last_detail`,
      [jobName, errorMessage || null]
    );
  },

  async listAll() {
    return dbLayer.all('SELECT * FROM cron_runs ORDER BY job_name');
  },
};

module.exports = { articles, assets, otxCache, cronRuns };
