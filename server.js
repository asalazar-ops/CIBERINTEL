// ─────────────────────────────────────────────────────────────────────────────
// CyberIntel EC — Servidor local de feeds RSS
// Corre en: http://localhost:3001
// ─────────────────────────────────────────────────────────────────────────────

const express   = require('express');
const cors      = require('cors');
const Parser    = require('rss-parser');
const fs        = require('fs');
const path      = require('path');
const dns       = require('dns').promises;
const https     = require('https');
const crypto    = require('crypto');
const sqlite3   = require('sqlite3').verbose();
require('dotenv').config();
const { ApifyClient } = require('apify-client');

// ─── INIT SQLITE PARA SENSORES ───────────────────────────────────────────────
const db = new sqlite3.Database(path.join(__dirname, 'sensors.db'), (err) => {
  if (err) console.error('[SQLite] Error al abrir la base de datos de sensores:', err.message);
  else {
    console.log('[SQLite] Conectado a la base de datos sensors.db');
    db.run(`CREATE TABLE IF NOT EXISTS sensor_alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_id TEXT,
      hostname TEXT,
      ip TEXT,
      event TEXT,
      severity TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS sensor_endpoints (
      agent_id TEXT PRIMARY KEY,
      hostname TEXT,
      ip TEXT,
      status TEXT,
      last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
      hardware_info TEXT,
      software_info TEXT
    )`);

    // --- NUEVAS TABLAS PARA DETECCIÓN DE COMPORTAMIENTO ---
    db.run(`CREATE TABLE IF NOT EXISTS sensor_telemetry (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_id TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      event_type TEXT, -- process, file, network, dns
      process_name TEXT,
      parent_process TEXT,
      target_path TEXT,
      dst_ip TEXT,
      dst_domain TEXT,
      risk_score INTEGER DEFAULT 0,
      raw_json TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS sensor_detections (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_id TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      detection_type TEXT, -- Infostealer, Beaconing, etc.
      severity TEXT,
      score INTEGER,
      details TEXT,
      behavior_chain TEXT -- JSON con los eventos correlacionados
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS sensor_behavior_scores (
      agent_id TEXT PRIMARY KEY,
      current_score INTEGER DEFAULT 0,
      last_alert_timestamp DATETIME,
      last_update DATETIME, -- Última vez que se recalculó el score (base del decaimiento)
      status TEXT DEFAULT 'low' -- low, suspicious, high, critical
    )`);

    // --- TABLA PARA BRAND PROTECTION (DETECCIÓN DE NUEVOS HALLAZGOS) ---
    db.run(`CREATE TABLE IF NOT EXISTS brand_protection_findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain TEXT,
      finding_url TEXT UNIQUE,
      title TEXT,
      description TEXT,
      source TEXT, -- APIFY, MANUAL, etc.
      severity TEXT,
      detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      is_new INTEGER DEFAULT 1 -- 1: Nuevo, 0: Ya visto/notificado
    )`);

    // Migraciones
    db.run(`ALTER TABLE sensor_endpoints ADD COLUMN hardware_info TEXT`, () => {});
    db.run(`ALTER TABLE sensor_endpoints ADD COLUMN software_info TEXT`, () => {});
    db.run(`ALTER TABLE sensor_telemetry ADD COLUMN mitre_id TEXT`, () => {});
    db.run(`ALTER TABLE sensor_telemetry ADD COLUMN mitre_tactic TEXT`, () => {});
    db.run(`ALTER TABLE sensor_telemetry ADD COLUMN mitre_technique TEXT`, () => {});
    db.run(`ALTER TABLE sensor_telemetry ADD COLUMN severity TEXT`, () => {});
    db.run(`ALTER TABLE sensor_behavior_scores ADD COLUMN last_update DATETIME`, () => {});
  }
});

const apifyClient = new ApifyClient({ token: process.env.APIFY_TOKEN });

const app    = express();
const parser = new Parser({
  timeout: 10000,
  headers: {
    'User-Agent': 'Mozilla/5.0 (compatible; CyberIntelEC/1.0)',
    'Accept': 'application/rss+xml, application/xml, text/xml, */*',
  },
  customFields: {
    item: ['description', 'summary', 'content:encoded'],
  }
});

app.use(cors({ origin: 'http://localhost:5173' }));
app.use(express.json());

// ─── AISLAMIENTO DE CANALES ──────────────────────────────────────────────────
// La misma app Express escucha en dos puertos: 3001 (dashboard, sólo loopback) y
// 8443 (sensores, expuesto a la LAN). Sin este filtro, el puerto de sensores
// también servía la API de gestión — incluido DELETE de endpoints y los recon de
// Apify — a cualquiera en la red. El canal de sensores sólo habla estas rutas.
const HTTPS_PORT = 8443;
const SENSOR_CHANNEL_PATHS = [
  '/api/sensors/report',
  '/api/sensors/heartbeat',
  '/api/sensors/sysinfo',
  '/api/sensors/telemetry',
  '/api/sensors/detection',
];

app.use((req, res, next) => {
  if (req.socket.localPort !== HTTPS_PORT) return next();

  const allowed = SENSOR_CHANNEL_PATHS.includes(req.path)
    || req.path.startsWith('/api/sensors/check/');
  if (allowed) return next();

  console.warn(`[AUTH] ⛔ Ruta fuera del canal de sensores rechazada en :${HTTPS_PORT}: ${req.method} ${req.path} desde ${req.ip}`);
  return res.status(404).json({ error: 'No disponible en el canal de sensores' });
});

// Logger global para depurar Webhooks y conexiones
app.use((req, res, next) => {
  if (req.path.startsWith('/api/webhooks')) {
    console.log(`[NETWORK] 📡 Petición entrante: ${req.method} ${req.originalUrl}`);
  }
  next();
});

const DATA_FILE = path.join(__dirname, 'data.json');
const ASSETS_FILE = path.join(__dirname, 'assets.json');

// ─── CARGA DE ASSETS ────────────────────────────────────────────────────────
let localAssets = [];
if (fs.existsSync(ASSETS_FILE)) {
  try {
    localAssets = JSON.parse(fs.readFileSync(ASSETS_FILE, 'utf-8'));
    console.log(`[ASSETS] Cargados ${localAssets.length} dominios monitoreados.`);
  } catch (err) { console.error('[ASSETS] Error leyendo assets.json:', err.message); }
}

function saveAssets() {
  fs.writeFileSync(ASSETS_FILE, JSON.stringify(localAssets, null, 2));
}

// ─── CONFIGURACIONES Y CRITERIOS ──────────────────────────────────────────────
const FEEDS = [
  { id: 'thn', name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews', region: 'Global', category: 'Cyber Global', color: '#64748b' },
  { id: 'bleeping', name: 'Bleeping Computer', url: 'https://www.bleepingcomputer.com/feed/', region: 'Global', category: 'Cyber Global', color: '#64748b' },
  { id: 'krebs', name: 'Krebs on Security', url: 'https://krebsonsecurity.com/feed/', region: 'Global', category: 'Cyber Global', color: '#64748b' },
  { id: 'secweek', name: 'SecurityWeek', url: 'https://feeds.securityweek.com/securityweek', region: 'Global', category: 'Cyber Global', color: '#64748b' },
  { id: 'darkreading', name: 'Dark Reading', url: 'https://www.darkreading.com/rss.xml', region: 'Global', category: 'Cyber Global', color: '#64748b' },
  { id: 'bankinfosec', name: 'BankInfoSecurity', url: 'https://www.bankinfosecurity.com/rss/news', region: 'Global', category: 'Banking Cyber', color: '#7dd3fc' },
  { id: 'govinfosec', name: 'GovInfoSecurity', url: 'https://www.govinfosecurity.com/rss-feeds', region: 'Global', category: 'Banking Cyber', color: '#7dd3fc' },
  { id: 'cisa', name: 'CISA Advisories', url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml', region: 'Global', category: 'Alertas Oficiales', color: '#a78bfa' },
  { id: 'nist', name: 'NIST Cybersecurity', url: 'https://www.nist.gov/blogs/cybersecurity-insights/rss.xml', region: 'Global', category: 'Alertas Oficiales', color: '#a78bfa' },
  { id: 'incibe', name: 'INCIBE (España)', url: 'https://www.incibe.es/rss.xml', region: 'Latinoamérica', category: 'Latam/España', color: '#f97316' },
  { id: 'cyberdefense', name: 'Cyber Defense Magazine', url: 'https://cyberdefensemagazine.com/feed/', region: 'Global', category: 'Cyber Global', color: '#64748b' },
  { id: 'gnews_ec_cyber', name: 'Noticias Ciberseguridad EC', url: 'https://news.google.com/rss/search?q=ciberseguridad+ecuador&hl=es-419&gl=EC&ceid=EC:es-419', region: 'Ecuador', category: 'Noticias Locales', color: '#ef4444' },
  { id: 'gnews_ec_banca', name: 'Fraude Bancario EC', url: 'https://news.google.com/rss/search?q=fraude+bancario+ecuador&hl=es-419&gl=EC&ceid=EC:es-419', region: 'Ecuador', category: 'Noticias Locales', color: '#ef4444' },
  { id: 'x_andnoticiacyber', name: 'X: @AndNoticiaCyber', url: 'https://rss.app/feeds/QIuhHT75XgsfY5JU.xml', region: 'Ecuador', category: 'Redes Sociales', color: '#0ea5e9' },
  { id: 'telegram_ciberciac', name: 'Telegram: @CiberCiac', url: 'https://rsshub.rssforever.com/telegram/channel/ciberciac', region: 'Ecuador', category: 'Redes Sociales', color: '#0088cc' }
];

const SECTOR_KEYWORDS = {
  'Banca':          ['bank', 'banco', 'banking', 'financial institution', 'credit union', 'entidad financiera', 'swift'],
  'Cooperativas':   ['cooperative', 'cooperativa', 'credit union', 'caja de ahorro', 'seps', 'cooprogreso', 'jep'],
  'Ransomware':     ['ransomware', 'ransom', 'lockbit', 'blackcat', 'alphv', 'cl0p', 'conti', 'ryuk', 'cifrado', 'encrypted'],
  'Phishing':       ['phishing', 'smishing', 'vishing', 'spear phishing', 'credential', 'fake login', 'correo falso'],
  'Fraude':         ['fraud', 'fraude', 'scam', 'estafa', 'identity theft', 'robo de identidad', 'skimming', 'carding'],
  'Fintech':        ['fintech', 'payment', 'crypto', 'blockchain', 'digital wallet', 'billetera', 'neobank'],
  'Infraestructura':['infrastructure', 'ddos', 'denial of service', 'critical infrastructure', 'power grid', 'ics', 'scada'],
  'Regulatorio':    ['regulation', 'regulación', 'compliance', 'gdpr', 'pci', 'dora', 'nis2', 'superintendencia', 'circular'],
  'Vulnerabilidad': ['vulnerability', 'vulnerabilidad', 'cve-', 'zero-day', 'patch', 'exploit', 'remote code'],
};

const SEVERITY_KEYWORDS = {
  'CRÍTICO': ['critical', 'crítico', 'emergency', 'emergencia', 'zero-day', 'active exploit', 'data breach', 'millions', 'millones', 'shutdown', 'cierre'],
  'ALTO':    ['high', 'alto', 'ransomware', 'breach', 'brecha', 'stolen', 'robado', 'leaked', 'filtrado', 'attack', 'ataque', 'compromised'],
  'MEDIO':   ['medium', 'medio', 'vulnerability', 'vulnerabilidad', 'phishing', 'fraud', 'fraude', 'warning', 'advertencia'],
  'BAJO':    ['low', 'bajo', 'patch', 'parche', 'update', 'actualización', 'advisory', 'awareness', 'concientización'],
};

const LATAM_KEYWORDS = ['ecuador', 'colombia', 'mexico', 'brasil', 'brazil', 'peru', 'chile', 'argentina', 'venezuela', 'latam', 'latinoamérica', 'latinoamerica', 'america latina', 'banco', 'cooperativa', 'seps', 'superbancos', 'ecucert'];

const THREAT_ACTORS = [
  'LockBit', 'BlackCat', 'ALPHV', 'Conti', 'Lazarus', 'APT28', 'Fancy Bear', 'APT29', 'Cozy Bear', 
  'Lapsus$', 'Hive', 'Cl0p', 'REvil', 'DarkSide', 'Medusa', 'Play', 'Royal', 'BianLian', 'RansomHouse',
  'BlackBasta', 'Akira', 'Rhysida', 'LemonDuck', 'Mustang Panda', 'Gorgon Group', 'APT37', 'APT41', 
  'Winnti', 'Sandworm', 'Turla', 'Kimsuky', 'MuddyWater', 'DarkHotel', 'Wizard Spider', 'TA505', 
  'Scattered Spider', 'UNC2452', 'Storm-0558', 'Volt Typhoon', 'Silk Typhoon'
];

function saveData() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(localData, null, 2));
}

function classify(item) {
  const text = `${item.title || ''} ${item.summary || item.contentSnippet || ''}`.toLowerCase();
  let sector = 'General';
  let sectorScore = 0;
  for (const [sec, keywords] of Object.entries(SECTOR_KEYWORDS)) {
    const matches = keywords.filter(kw => text.includes(kw.toLowerCase())).length;
    if (matches > sectorScore) { sectorScore = matches; sector = sec; }
  }
  let severity = 'BAJO';
  for (const [sev, keywords] of Object.entries(SEVERITY_KEYWORDS)) {
    if (keywords.some(kw => text.includes(kw.toLowerCase()))) {
      severity = sev;
      break;
    }
  }
  const isLatam = LATAM_KEYWORDS.some(kw => text.includes(kw));
  let actor = null;
  for (const a of THREAT_ACTORS) {
    if (text.includes(a.toLowerCase())) { actor = a; break; }
  }
  return { sector, severity, isLatam, actor };
}

// ─── CARGA Y MIGRACIÓN DE DATA ───────────────────────────────────────────────
let localData = [];
if (fs.existsSync(DATA_FILE)) {
  try {
    localData = JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8'));
    console.log(`[DATA] Cargados ${localData.length} artículos. Re-clasificando...`);
    
    // Migración: Re-detectar actores y regiones en data antigua si es necesario
    localData = localData.map(item => {
      const { sector, severity, isLatam, actor } = classify(item);
      return { 
        ...item, 
        actor: item.actor || actor, 
        severity: (item.severity === 'BAJO' || !item.severity) ? severity : item.severity,
        region: (isLatam && item.region === 'Global') ? 'Latinoamérica' : item.region
      };
    });
    fs.writeFileSync(DATA_FILE, JSON.stringify(localData, null, 2));
    
  } catch (err) {
    console.error('[DATA] Error procesando data.json:', err.message);
  }
}

// ─── LÓGICA DE ANÁLISIS DE ASSETS (DOMINIOS) ─────────────────────────────────
const COMMON_SUBDOMAINS = [
  'www', 'mail', 'vpn', 'remote', 'ns1', 'ns2', 'cloud', 'portal', 'dev', 'api', 'secure', 'test', 
  'webmail', 'exchange', 'autodiscover', 'owa', 'admin', 'blog', 'shop', 'm', 'en', 'static', 'cdn',
  'api-dev', 'staging', 'qa', 'support', 'help', 'docs', 'assets', 'git', 'gitlab', 'jenkins',
  'monitor', 'status', 'zabbix', 'grafana', 'kibana', 'elastic', 'db', 'database', 'sql', 'mysql',
  'internal', 'intranet', 'staff', 'hr', 'mobile', 'app', 'client', 'portal-empresa', 'portal-banco',
  'banca', 'bancamovil', 'cooperativa', 'virtual', 'transacciones', 'servicios', 'pagos', 'socios',
  'moodle', 'aula', 'campus', 'correo', 'files', 'share', 'backup', 'ws', 'webservices', 'proxy'
];

const UA_HEADER = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberIntelEC/2.0' };

function fetchCrtSh(domain) {
  return new Promise((resolve) => {
    console.log(`[DNS] [crt.sh] Consultando logs de certificados para ${domain}...`);
    const url = `https://crt.sh/?q=%.${domain}&output=json`;
    https.get(url, { headers: UA_HEADER }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (!Array.isArray(json)) return resolve([]);
          const subs = json.flatMap(e => [
            ...(e.common_name ? [e.common_name] : []),
            ...(e.name_value ? e.name_value.split('\n') : [])
          ]).map(s => s.toLowerCase().trim());
          const clean = [...new Set(subs)].filter(s => s.endsWith(domain) && s !== domain && !s.includes('*'));
          console.log(`[DNS] [crt.sh] Encontrados ${clean.length} candidatos.`);
          resolve(clean);
        } catch (e) { resolve([]); }
      });
    }).on('error', () => resolve([]));
    setTimeout(() => resolve([]), 20000); // 20s para crt.sh que es lento
  });
}

function fetchHackerTarget(domain) {
  return new Promise((resolve) => {
    console.log(`[DNS] [HackerTarget] Consultando para ${domain}...`);
    const url = `https://api.hackertarget.com/hostsearch/?q=${domain}`;
    https.get(url, { headers: UA_HEADER }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          if (data.includes('API count exceeded')) {
            console.log(`[DNS] [HackerTarget] Límite de API excedido.`);
            return resolve([]);
          }
          const lines = data.split('\n');
          const subs = lines.map(l => l.split(',')[0].toLowerCase().trim()).filter(s => s && s.endsWith(domain) && s !== domain);
          console.log(`[DNS] [HackerTarget] Encontrados ${subs.length} candidatos.`);
          resolve(subs);
        } catch (e) { resolve([]); }
      });
    }).on('error', () => resolve([]));
    setTimeout(() => resolve([]), 10000);
  });
}

function fetchAlienVault(domain) {
  return new Promise((resolve) => {
    console.log(`[DNS] [AlienVault] Consultando Passive DNS para ${domain}...`);
    const url = `https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns`;
    https.get(url, { headers: UA_HEADER }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (!json.passive_dns) return resolve([]);
          const subs = json.passive_dns.map(entry => entry.hostname.toLowerCase()).filter(s => s.endsWith(domain) && s !== domain);
          const clean = [...new Set(subs)];
          console.log(`[DNS] [AlienVault] Encontrados ${clean.length} candidatos.`);
          resolve(clean);
        } catch (e) { resolve([]); }
      });
    }).on('error', () => resolve([]));
    setTimeout(() => resolve([]), 10000);
  });
}

function fetchAnubis(domain) {
  return new Promise((resolve) => {
    console.log(`[DNS] [Anubis] Consultando para ${domain}...`);
    const url = `https://jldc.me/anubis/subdomains/${domain}`;
    https.get(url, { headers: UA_HEADER }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (!Array.isArray(json)) return resolve([]);
          const subs = json.map(s => s.toLowerCase().trim()).filter(s => s.endsWith(domain) && s !== domain);
          console.log(`[DNS] [Anubis] Encontrados ${subs.length} candidatos.`);
          resolve(subs);
        } catch (e) { resolve([]); }
      });
    }).on('error', () => resolve([]));
    setTimeout(() => resolve([]), 12000);
  });
}

function fetchOmnisint(domain) {
  return new Promise((resolve) => {
    console.log(`[DNS] [Omnisint] Consultando para ${domain}...`);
    const url = `https://sonar.omnisint.io/subdomains/${domain}`;
    https.get(url, { headers: UA_HEADER }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (!Array.isArray(json)) return resolve([]);
          console.log(`[DNS] [Omnisint] Encontrados ${json.length} candidatos.`);
          resolve(json.filter(s => s.endsWith(domain)));
        } catch (e) { resolve([]); }
      });
    }).on('error', () => resolve([]));
    setTimeout(() => resolve([]), 10000);
  });
}

function fetchSubdomainCenter(domain) {
  return new Promise((resolve) => {
    console.log(`[DNS] [SubdomainCenter] Consultando para ${domain}...`);
    const url = `https://subdomain.center/api/index.php?domain=${domain}`;
    https.get(url, { headers: UA_HEADER }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (!Array.isArray(json)) return resolve([]);
          console.log(`[DNS] [SubdomainCenter] Encontrados ${json.length} candidatos.`);
          resolve(json.filter(s => s.endsWith(domain)));
        } catch (e) { resolve([]); }
      });
    }).on('error', () => resolve([]));
    setTimeout(() => resolve([]), 10000);
  });
}

function fetchRapidDNS(domain) {
  return new Promise((resolve) => {
    console.log(`[DNS] [RapidDNS] Consultando para ${domain}...`);
    const url = `https://rapiddns.io/subdomain/${domain}?full=1`;
    https.get(url, { headers: UA_HEADER }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          // RapidDNS requiere un regex para extraer del HTML
          const regex = new RegExp(`[a-zA-Z0-9.-]+\\.${domain.replace(/\./g, '\\.')}`, 'g');
          const matches = data.match(regex) || [];
          const clean = [...new Set(matches.map(m => m.toLowerCase()))];
          console.log(`[DNS] [RapidDNS] Encontrados ${clean.length} candidatos.`);
          resolve(clean);
        } catch (e) { resolve([]); }
      });
    }).on('error', () => resolve([]));
    setTimeout(() => resolve([]), 15000);
  });
}

function fetchUrlScan(domain) {
  return new Promise((resolve) => {
    console.log(`[DNS] [UrlScan] Consultando para ${domain}...`);
    const url = `https://urlscan.io/api/v1/search/?q=domain:${domain}&size=100`;
    https.get(url, { headers: UA_HEADER }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (!json.results) return resolve([]);
          const subs = json.results.map(r => r.page.domain.toLowerCase()).filter(s => s.endsWith(domain));
          const clean = [...new Set(subs)];
          console.log(`[DNS] [UrlScan] Encontrados ${clean.length} candidatos.`);
          resolve(clean);
        } catch (e) { resolve([]); }
      });
    }).on('error', () => resolve([]));
    setTimeout(() => resolve([]), 10000);
  });
}

function fetchDnstwister(domain) {
  return new Promise((resolve) => {
    const domainHex = Buffer.from(domain).toString('hex');
    console.log(`[DNS] Consultando dnstwister para ${domain}...`);
    const url = `https://dnstwister.report/api/fuzz/${domainHex}`;
    https.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (!json.fuzzy_domains) return resolve([]);
          // dnstwister devuelve dominios similares, algunos ya traen resolución
          resolve(json.fuzzy_domains.map(d => d.domain));
        } catch (e) { resolve([]); }
      });
    }).on('error', () => resolve([]));
    setTimeout(() => resolve([]), 15000);
  });
}

async function checkZoneTransfer(domain) {
  try {
    const nsRecords = await dns.resolveNs(domain).catch(() => []);
    if (nsRecords.length === 0) return [];
    console.log(`[DNS] Verificando AXFR en ${nsRecords[0]}...`);
    return [];
  } catch (e) { return []; }
}

async function autoScanAssets() {
  if (localAssets.length === 0) return;
  console.log(`[MONITOR] Iniciando escaneo automático de ${localAssets.length} assets...`);
  for (const asset of localAssets) {
    try {
      // Pasar subdominios actuales para no perderlos si una fuente falla temporalmente
      const result = await scanDomain(asset.domain, asset.subdomains || []);
      Object.assign(asset, result);
      console.log(`  ✓ ${asset.domain} actualizado automáticamente.`);
    } catch (err) {
      console.error(`  ✗ Error en auto-escaneo de ${asset.domain}:`, err.message);
    }
  }
  saveAssets();
}

// Iniciar monitoreo automático cada 6 horas
setInterval(autoScanAssets, 6 * 60 * 60 * 1000);

function generateTypos(domain) {
  const [name, tld] = domain.split('.');
  if (!name) return [];
  const typos = new Set();
  
  // 1. Homoglyphs (Suplantación visual)
  const glyphs = { 'a':['4','@'], 'e':['3'], 'i':['1','l','j'], 'o':['0'], 's':['5','$'], 't':['7'] };
  for (let i = 0; i < name.length; i++) {
    const char = name[i];
    if (glyphs[char]) {
      glyphs[char].forEach(g => {
        const typo = name.substring(0, i) + g + name.substring(i + 1);
        typos.add(`${typo}.${tld}`);
      });
    }
  }

  // 2. Transposition (Error de teclado)
  for (let i = 0; i < name.length - 1; i++) {
    const typo = name.substring(0, i) + name[i+1] + name[i] + name.substring(i+2);
    typos.add(`${typo}.${tld}`);
  }

  // 3. Omission (Falta una letra)
  for (let i = 0; i < name.length; i++) {
    const typo = name.substring(0, i) + name.substring(i + 1);
    if (typo) typos.add(`${typo}.${tld}`);
  }

  // 4. Repetition (Doble tecla)
  for (let i = 0; i < name.length; i++) {
    const typo = name.substring(0, i) + name[i] + name[i] + name.substring(i+1);
    typos.add(`${typo}.${tld}`);
  }

  // 5. Common Phishing Suffixes
  const suffixes = ['-login', '-sec', '-secure', '-support', '-ec', 'online', 'cloud'];
  suffixes.forEach(s => {
    typos.add(`${name}${s}.${tld}`);
    typos.add(`${name}-${s}.${tld}`);
  });

  // 6. Common Phishing TLDs
  const badTlds = ['net', 'org', 'xyz', 'info', 'online', 'biz'];
  badTlds.forEach(bt => typos.add(`${name}.${bt}`));

  return Array.from(typos).filter(t => t !== domain);
}

async function scanDomain(domain, existingSubdomains = []) {
  const result = {
    spf: { status: 'missing', record: null },
    dmarc: { status: 'missing', record: null },
    subdomains: [], // Se llenará con objetos { name, status, lastSeen }
    impersonations: [],
    riskScore: 0,
    lastScan: new Date().toISOString()
  };

  // Convertir subdominios existentes a mapa para fácil acceso
  const subMap = new Map();
  existingSubdomains.forEach(s => {
    const name = typeof s === 'string' ? s : s.name;
    subMap.set(name, { name, status: 'offline', lastSeen: s.lastSeen || result.lastScan });
  });

  try {
    // 1. Check SPF & DMARC
    const [txtRoot, txtDmarc] = await Promise.all([
      dns.resolveTxt(domain).catch(() => []),
      dns.resolveTxt(`_dmarc.${domain}`).catch(() => [])
    ]);

    const spfRecord = txtRoot.flat().find(r => r.startsWith('v=spf1'));
    if (spfRecord) result.spf = { status: 'valid', record: spfRecord };
    else result.riskScore += 30;

    const dmarcRecord = txtDmarc.flat().find(r => r.startsWith('v=DMARC1'));
    if (dmarcRecord) result.dmarc = { status: 'valid', record: dmarcRecord };
    else result.riskScore += 40;

    // 3. Subdomain Discovery
    console.log(`[SCAN] [${domain}] Iniciando inteligencia de activos avanzada...`);
    const [passiveCrt, passiveHT, passiveOTX, passiveAnubis, passiveOmni, passiveSC, passiveRapid, passiveUrlScan] = await Promise.all([
      fetchCrtSh(domain),
      fetchHackerTarget(domain),
      fetchAlienVault(domain),
      fetchAnubis(domain),
      fetchOmnisint(domain),
      fetchSubdomainCenter(domain),
      fetchRapidDNS(domain),
      fetchUrlScan(domain)
    ]);

    const activeSubs = [];
    const batchSize = 30;
    for (let i = 0; i < COMMON_SUBDOMAINS.length; i += batchSize) {
      const batch = COMMON_SUBDOMAINS.slice(i, i + batchSize);
      await Promise.all(batch.map(async (sub) => {
        try {
          const target = `${sub}.${domain}`;
          await dns.resolveAny(target);
          activeSubs.push(target);
        } catch (e) { /* no existe */ }
      }));
    }

    const candidates = [...new Set([
      ...passiveCrt, ...passiveHT, ...passiveOTX, ...passiveAnubis, 
      ...passiveOmni, ...passiveSC, ...passiveRapid, ...passiveUrlScan,
      ...activeSubs
    ])];
    
    console.log(`[DNS] [${domain}] Candidatos totales de 8 fuentes: ${candidates.length}`);

    // Validación final paralela (Más estricta: requiere IP o CNAME)
    for (let i = 0; i < candidates.length; i += batchSize) {
      const batch = candidates.slice(i, i + batchSize);
      await Promise.all(batch.map(async (sub) => {
        try {
          // Intentar resolver registros que impliquen un host activo
          const [a, aaaa, cname, mx] = await Promise.all([
            dns.resolve4(sub).catch(() => []),
            dns.resolve6(sub).catch(() => []),
            dns.resolveCname(sub).catch(() => []),
            dns.resolveMx(sub).catch(() => [])
          ]);

          const hasHost = a.length > 0 || aaaa.length > 0 || cname.length > 0 || mx.length > 0;

          if (hasHost) {
            subMap.set(sub, { 
              name: sub, 
              status: 'online', 
              lastSeen: result.lastScan,
              ips: [...a, ...aaaa]
            });
          } else {
            // Si tiene registros DNS (resolveAny) pero no son de host (A/CNAME/MX)
            // lo tratamos como offline para el usuario final para evitar ruido
            if (subMap.has(sub)) {
              subMap.get(sub).status = 'offline';
            }
          }
        } catch (e) {
          if (subMap.has(sub)) {
            subMap.get(sub).status = 'offline';
          }
        }
      }));
    }

    result.subdomains = Array.from(subMap.values()).sort((a, b) => a.name.localeCompare(b.name));
    console.log(`[DNS] [${domain}] Escaneo finalizado. Total acumulado: ${result.subdomains.length}`);

    // 4. Typosquatting Check (Algorithmic Analysis + dnstwister)
    console.log(`[SCAN] Analizando variantes de suplantación para ${domain}...`);
    
    const [algoVariants, externalVariants] = await Promise.all([
      generateTypos(domain),
      fetchDnstwister(domain)
    ]);

    const allVariants = [...new Set([...algoVariants, ...externalVariants])];
    console.log(`[DNS] Analizando ${allVariants.length} variantes posibles (Algoritmo + dnstwister).`);

    // Limitar validación a una muestra representativa o los más probables para no bloquear
    const topVariants = allVariants.slice(0, 70); 
    
    for (const v of topVariants) {
      try {
        const [addresses, mxRecords] = await Promise.all([
          dns.resolve(v).catch(() => []),
          dns.resolveMx(v).catch(() => [])
        ]);

        if (addresses.length > 0 || mxRecords.length > 0) {
          result.impersonations.push({ 
            domain: v, 
            status: 'active', 
            hasMail: mxRecords.length > 0,
            risk: mxRecords.length > 0 ? 'CRITICAL' : 'HIGH' 
          });
          result.riskScore += mxRecords.length > 0 ? 30 : 20;
        }
      } catch (e) { /* libre */ }
    }
    console.log(`[DNS] Suplantaciones activas detectadas: ${result.impersonations.length}`);

    result.riskScore = Math.min(result.riskScore, 100);
    return result;
  } catch (err) {
    console.error(`[SCAN] Error escaneando ${domain}:`, err.message);
    return result;
  }
}


function stripHtml(html = '') {
  return html.replace(/<[^>]*>/g, '').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();
}

function extractTags(item, sector) {
  const text = `${item.title || ''} ${item.contentSnippet || ''}`.toLowerCase();
  const tags = [];
  const tagKeywords = ['ransomware', 'phishing', 'malware', 'ddos', 'zero-day', 'apt', 'data breach', 'vulnerability', 'exploit', 'botnet', 'trojan', 'social engineering', 'mfa bypass', 'credential stuffing', 'swift', 'cve', 'patch', 'bypass', 'escalation', 'rce', 'sqli', 'xss'];
  for (const kw of tagKeywords) {
    if (text.includes(kw) && tags.length < 3) tags.push(kw.toUpperCase().replace(' ', '-'));
  }
  if (tags.length === 0 && sector !== 'General') tags.push(sector.toUpperCase());
  return tags;
}

// ─── ENDPOINT: GET /api/feeds ─────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.send('🛡️ CyberIntel EC API is Running. Status: OK. Use /api/feeds or /api/assets');
});

app.get('/api/feeds', async (req, res) => {
  console.log(`[${new Date().toLocaleTimeString()}] 📡 Obteniendo feeds RSS...`);
  const feedStatus = {};

  // 1. Fetch de todas las fuentes
  await Promise.all(FEEDS.map(async (feed) => {
    try {
      const parsed = await parser.parseURL(feed.url);
      const items = parsed.items || [];
      let addedCount = 0;

      for (const item of items) {
        // Generar un ID único basado en el enlace o título
        const uniqueId = item.guid || item.id || item.link || item.title;
        if (!uniqueId) continue;

        // Comprobar si ya existe
        const exists = localData.some(d => d.uniqueId === uniqueId);
        if (!exists) {
          const { sector, severity, isLatam, actor } = classify(item);
          const region = isLatam ? 'Latinoamérica' : feed.region;
          const parsedDate = item.isoDate || item.pubDate;
          
          localData.push({
            uniqueId, // Para evitar duplicados
            id: `${feed.id}-${Math.random().toString(36).slice(2, 7)}`,
            feedId: feed.id,
            source: feed.name,
            category: feed.category,
            color: feed.color,
            region,
            sector,
            actor,
            severity,
            title: item.title || '(Sin título)',
            summary: stripHtml(item.contentSnippet || item.description || item.summary || '').slice(0, 500),
            link: item.link || '#',
            date: parsedDate || new Date().toISOString(), // Fallback a hoy
            tags: extractTags(item, sector),
          });
          addedCount++;
        }
      }
      feedStatus[feed.id] = { status: 'ok', added: addedCount };
      if (addedCount > 0) console.log(`  ✓ ${feed.name}: +${addedCount} nuevos`);
    } catch (err) {
      feedStatus[feed.id] = { status: 'error', message: err.message };
      console.log(`  ✗ ${feed.name}: ${err.message}`);
    }
  }));

  // Guardar datos después de cada actualización
  saveData();

  // 2. Separar Recientes (<=60 días) vs Histórico (>60 días)
  const now = Date.now();
  const SIXTY_DAYS_MS = 60 * 24 * 60 * 60 * 1000;

  const recientes = [];
  const historico = [];

  // Calcular tiempos relativos para respuesta y separar
  const timeAgo = (dateStr) => {
    try {
      const seconds = (Date.now() - new Date(dateStr).getTime()) / 1000;
      if (seconds < 3600)  return `hace ${Math.floor(seconds / 60)}min`;
      if (seconds < 86400) return `hace ${Math.floor(seconds / 3600)}h`;
      if (seconds < 604800) return `hace ${Math.floor(seconds / 86400)}d`;
      return new Date(dateStr).toLocaleDateString('es-EC', { day: '2-digit', month: 'short', year: 'numeric' });
    } catch { return 'Fecha desconocida'; }
  };

  localData.forEach(item => {
    const itemTime = new Date(item.date).getTime();
    const age = now - itemTime;
    const responseItem = { ...item, dateAgo: timeAgo(item.date) };

    if (age <= SIXTY_DAYS_MS) recientes.push(responseItem);
    else historico.push(responseItem);
  });

  // Ordenar ambos arreglos por fecha (más reciente a más antiguo)
  const sorter = (a, b) => new Date(b.date) - new Date(a.date);
  recientes.sort(sorter);
  historico.sort(sorter);

  console.log(`[API] Respondidos: ${recientes.length} Recientes | ${historico.length} Histórico\n`);

  res.json({
    success: true,
    total: localData.length,
    recientesCount: recientes.length,
    historicoCount: historico.length,
    feedStatus,
    recientes,
    historico,
    feedsMeta: FEEDS.map(f => ({ id: f.id, name: f.name })),
    timestamp: new Date().toISOString(),
  });
});

// ─── ENDPOINT: DELETE /api/feeds (Limpiar Datos) ──────────────────────────────
app.delete('/api/feeds', (req, res) => {
  const { filterType, filterValue } = req.body;
  const initialLength = localData.length;

  if (filterType === 'all') {
    localData = [];
  } else if (filterType === 'older_than_60') {
    const now = Date.now();
    const SIXTY_DAYS_MS = 60 * 24 * 60 * 60 * 1000;
    localData = localData.filter(item => (now - new Date(item.date).getTime()) <= SIXTY_DAYS_MS);
  } else if (filterType === 'older_than_365') {
    const now = Date.now();
    const YEAR_MS = 365 * 24 * 60 * 60 * 1000;
    localData = localData.filter(item => (now - new Date(item.date).getTime()) <= YEAR_MS);
  } else if (filterType === 'feedId' && filterValue) {
    localData = localData.filter(item => item.feedId !== filterValue);
  } else if (filterType === 'historico_all') {
    const now = Date.now();
    const SIXTY_DAYS_MS = 60 * 24 * 60 * 60 * 1000;
    localData = localData.filter(item => (now - new Date(item.date).getTime()) <= SIXTY_DAYS_MS);
  }

  saveData();
  const deleted = initialLength - localData.length;
  console.log(`[DELETE] Limpiados ${deleted} registros. (Filtro: ${filterType})`);

  res.json({ success: true, deleted, remaining: localData.length });
});

// ─── ENDPOINTS: GESTIÓN DE ASSETS (DOMINIOS) ──────────────────────────────────
app.get('/api/assets', (req, res) => {
  res.json(localAssets);
});

app.post('/api/assets', async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Dominio requerido' });
  
  // Evitar duplicados
  if (localAssets.some(a => a.domain.toLowerCase() === domain.toLowerCase())) {
    return res.status(400).json({ error: 'El dominio ya está en monitoreo' });
  }

  const id = Math.random().toString(36).slice(2, 9);
  const scanResult = await scanDomain(domain);
  const newAsset = { id, domain, ...scanResult };
  
  localAssets.push(newAsset);
  saveAssets();
  res.json(newAsset);
});

app.get('/api/assets/scan/:id', async (req, res) => {
  const asset = localAssets.find(a => a.id === req.params.id);
  if (!asset) return res.status(404).json({ error: 'Asset no encontrado' });
  
  // Persistir hallazgos previos
  const scanResult = await scanDomain(asset.domain, asset.subdomains || []);
  Object.assign(asset, scanResult);
  saveAssets();
  res.json(asset);
});

app.post('/api/assets/recon/:id', async (req, res) => {
  const asset = localAssets.find(a => a.id === req.params.id);
  if (!asset) return res.status(404).json({ error: 'Asset no encontrado' });

  console.log(`[APIFY] Iniciando Deep Recon para: ${asset.domain}`);
  try {
    // Ejecutar Google Search Scraper
    const run = await apifyClient.actor('apify/google-search-scraper').call({
      queries: `${asset.domain} phishing OR fraud OR login`,
      maxPagesPerQuery: 1,
      resultsPerPage: 10,
      mobileResults: false,
      languageCode: 'es',
      maxConcurrency: 1
    });

    const { items } = await apifyClient.dataset(run.defaultDatasetId).listItems();
    
    // Simplificar resultados para el frontend
    const searchResults = items.flatMap(item => 
      (item.organicResults || []).map(r => ({
        title: r.title,
        url: r.url,
        description: r.description
      }))
    );

    res.json({ success: true, results: searchResults });
  } catch (err) {
    console.error('[APIFY] Error:', err.message);
    res.status(500).json({ error: 'Error consultando Apify', details: err.message });
  }
});

app.post('/api/assets/facebook-recon/:id', async (req, res) => {
  const asset = localAssets.find(a => a.id === req.params.id);
  if (!asset) return res.status(404).json({ error: 'Asset no encontrado' });

  console.log(`[APIFY] Iniciando Facebook Brand Protection (Google) para: ${asset.domain}`);
  try {
    // Estrategia: usar Google Search con queries site:facebook.com
    // Esto es más confiable que un actor de Facebook directo
    const brandName = asset.domain.split('.')[0];
    const queries = [
      `site:facebook.com "${brandName}"`,
      `site:facebook.com "${asset.domain}"`,
      `site:facebook.com "${brandName}" banco OR cooperativa OR oficial OR soporte`
    ].join('\n');

    const run = await apifyClient.actor('apify/google-search-scraper').call({
      queries,
      maxPagesPerQuery: 1,
      resultsPerPage: 10,
      mobileResults: false,
      languageCode: 'es',
      maxConcurrency: 1
    });

    const { items } = await apifyClient.dataset(run.defaultDatasetId).listItems();

    const facebookResults = items.flatMap(item =>
      (item.organicResults || [])
        .filter(r => r.url && r.url.includes('facebook.com'))
        .map(r => ({
          title: r.title || 'Página de Facebook',
          url: r.url,
          description: r.description || 'Sin descripción disponible'
        }))
    );

    console.log(`[APIFY] Facebook Recon: ${facebookResults.length} resultados encontrados para ${asset.domain}`);
    res.json({ success: true, results: facebookResults });
  } catch (err) {
    console.error('[APIFY] FB Error:', err.message);
    res.status(500).json({ error: 'Error consultando Facebook via Apify Google Search', details: err.message });
  }
});

// ─── FACEBOOK SEARCH SCRAPER (con caché persistente) ──────────────────────────
// GET: devuelve caché si existe, sin llamar a Apify
app.get('/api/assets/fb-scraper/:id', (req, res) => {
  const asset = localAssets.find(a => a.id === req.params.id);
  if (!asset) return res.status(404).json({ error: 'Asset no encontrado' });

  if (asset.fbScraperCache && asset.fbScraperCache.results) {
    return res.json({ 
      success: true, 
      results: asset.fbScraperCache.results,
      cachedAt: asset.fbScraperCache.cachedAt,
      fromCache: true
    });
  }
  res.json({ success: true, results: [], fromCache: false });
});

// POST: ejecuta un escaneo real con Apify y lo persiste
app.post('/api/assets/fb-scraper/:id', async (req, res) => {
  const asset = localAssets.find(a => a.id === req.params.id);
  if (!asset) return res.status(404).json({ error: 'Asset no encontrado' });

  // Extraer la palabra clave principal del dominio (ej: micooperativa.fin.ec -> micooperativa)
  const brandKeyword = asset.domain.split('.')[0];
  console.log(`[APIFY] Iniciando Brand Protection Monitor para: ${brandKeyword} (Dominio: ${asset.domain})`);
  
  try {
    const run = await apifyClient.actor('ryanclinton/brand-protection-monitor').call({
      searchQueries: [brandKeyword],
      maxResults: 20,
      includeSocialMedia: true,
      includeMarketplaces: true,
      includeDomains: true,
      proxyConfiguration: { useApifyProxy: true }
    });

    const { items } = await apifyClient.dataset(run.defaultDatasetId).listItems();

    const results = items.map(item => ({
      title: item.title || item.siteName || 'Amenaza Detectada',
      url: item.url || item.sourceUrl || '',
      description: item.description || item.snippet || `Detección de marca para ${brandKeyword}`,
      likes: item.engagement || null,
      type: item.sourceType || 'detection',
      verified: item.isVerified || false,
      riskLevel: item.riskScore || 'N/A'
    })).filter(r => r.url);

    // Guardar en caché dentro del asset y persistir en disco
    asset.fbScraperCache = {
      results,
      cachedAt: new Date().toISOString(),
      domain: asset.domain,
      keyword: brandKeyword
    };
    saveAssets();

    console.log(`[APIFY] Brand Monitor: ${results.length} detecciones encontradas para ${brandKeyword}`);
    res.json({ success: true, results, cachedAt: asset.fbScraperCache.cachedAt, fromCache: false });
  } catch (err) {
    console.error('[APIFY] Brand Monitor Error:', err.message);
    res.status(500).json({ error: 'Error en Brand Protection Monitor', details: err.message });
  }
});

app.delete('/api/assets/:id', (req, res) => {
  console.log(`[ASSETS] Petición para eliminar asset: ${req.params.id}`);
  const initialCount = localAssets.length;
  localAssets = localAssets.filter(a => a.id !== req.params.id);
  saveAssets();
  console.log(`[ASSETS] Asset eliminado. Restantes: ${localAssets.length}`);
  res.json({ success: true, deleted: initialCount > localAssets.length });
});

// ─── INTEGRACIÓN ALIENVAULT OTX ───────────────────────────────────────────────
const OTX_API_KEY = process.env.OTX_API_KEY || '';
const OTX_BASE = 'https://otx.alienvault.com/api/v1';
const OTX_CACHE_TTL = 15 * 60 * 1000; // 15 minutos de caché
let otxCache = { pulses: [], indicators: [], lastFetch: 0, loading: false };

async function fetchOTX(endpoint) {
  if (!OTX_API_KEY) throw new Error('OTX_API_KEY no configurada');
  const url = `${OTX_BASE}${endpoint}`;
  const resp = await fetch(url, {
    headers: { 
      'X-OTX-API-KEY': OTX_API_KEY, 
      'Accept': 'application/json',
      'User-Agent': 'CyberIntel-EC-Sensor/1.0'
    }
  });
  if (!resp.ok) throw new Error(`OTX API error: ${resp.status} ${resp.statusText}`);
  return resp.json();
}

async function refreshOTXData() {
  if (otxCache.loading) return;
  otxCache.loading = true;
  console.log('[OTX] Actualizando datos desde AlienVault OTX...');
  
  try {
    // Fetch pulses suscritos (global) + búsqueda específica LATAM
    const [subscribedData, latamData] = await Promise.all([
      fetchOTX('/pulses/subscribed?limit=20&modified_since=' + new Date(Date.now() - 30*24*60*60*1000).toISOString()).catch(() => ({ results: [] })),
      fetchOTX('/pulses/search?q=ecuador+colombia+latam+latinoamerica&limit=15&sort=-modified').catch(() => ({ results: [] })),
    ]);

    const allPulses = [];
    const seenIds = new Set();
    
    // Procesar ambas fuentes, deduplicando por ID
    for (const pulse of [...(subscribedData.results || []), ...(latamData.results || [])]) {
      if (seenIds.has(pulse.id)) continue;
      seenIds.add(pulse.id);
      allPulses.push({
        id: pulse.id,
        name: pulse.name,
        description: (pulse.description || '').substring(0, 300),
        author: pulse.author_name || 'Unknown',
        created: pulse.created,
        modified: pulse.modified,
        tags: pulse.tags || [],
        tlp: pulse.tlp || 'white',
        adversary: pulse.adversary || null,
        industries: pulse.industries || [],
        targeted_countries: pulse.targeted_countries || [],
        indicator_count: (pulse.indicators || []).length,
        source: (pulse.targeted_countries || []).some(c => ['Ecuador', 'Colombia', 'Mexico', 'Brazil', 'Peru', 'Chile', 'Argentina'].includes(c)) ? 'LATAM' : 'Global'
      });
    }
    
    // Extraer indicadores únicos
    const allIndicators = [];
    const seenIndicators = new Set();
    
    for (const pulse of [...(subscribedData.results || []), ...(latamData.results || [])]) {
      for (const ind of (pulse.indicators || []).slice(0, 50)) {
        const key = `${ind.type}:${ind.indicator}`;
        if (seenIndicators.has(key)) continue;
        seenIndicators.add(key);
        allIndicators.push({
          type: ind.type,
          indicator: ind.indicator,
          title: ind.title || '',
          description: ind.description || '',
          pulse_name: pulse.name,
          pulse_id: pulse.id,
          created: ind.created || pulse.created,
          is_active: ind.is_active !== undefined ? ind.is_active : 1,
          source: (pulse.targeted_countries || []).some(c => ['Ecuador', 'Colombia', 'Mexico', 'Brazil', 'Peru', 'Chile', 'Argentina'].includes(c)) ? 'LATAM' : 'Global'
        });
      }
    }
    
    otxCache = {
      pulses: allPulses,
      indicators: allIndicators,
      lastFetch: Date.now(),
      loading: false
    };
    
    console.log(`[OTX] ✓ ${allPulses.length} pulses, ${allIndicators.length} indicadores cargados.`);
  } catch (err) {
    console.error('[OTX] Error:', err.message);
    otxCache.loading = false;
  }
}

// Cargar OTX al inicio del servidor
if (OTX_API_KEY) {
  setTimeout(() => refreshOTXData(), 3000);
} else {
  console.warn('[OTX] ⚠ OTX_API_KEY no definida en .env — Integración OTX deshabilitada.');
}

// --- Endpoints OTX ---
app.get('/api/otx/pulses', async (req, res) => {
  if (!OTX_API_KEY) return res.status(503).json({ error: 'OTX no configurado' });
  if (Date.now() - otxCache.lastFetch > OTX_CACHE_TTL) await refreshOTXData();
  res.json({ success: true, count: otxCache.pulses.length, pulses: otxCache.pulses, cachedAt: otxCache.lastFetch });
});

app.get('/api/otx/indicators', async (req, res) => {
  if (!OTX_API_KEY) return res.status(503).json({ error: 'OTX no configurado' });
  if (Date.now() - otxCache.lastFetch > OTX_CACHE_TTL) await refreshOTXData();
  
  let filtered = otxCache.indicators;
  const { type, source, limit } = req.query;
  if (type) filtered = filtered.filter(i => i.type === type);
  if (source) filtered = filtered.filter(i => i.source === source);
  const maxResults = Math.min(parseInt(limit) || 500, 1000);
  
  // Estadísticas por tipo
  const typeStats = {};
  otxCache.indicators.forEach(i => { typeStats[i.type] = (typeStats[i.type] || 0) + 1; });
  
  res.json({
    success: true,
    total: otxCache.indicators.length,
    filtered: filtered.length,
    types: typeStats,
    indicators: filtered.slice(0, maxResults),
    cachedAt: otxCache.lastFetch
  });
});

app.get('/api/otx/adversaries', async (req, res) => {
  if (!OTX_API_KEY) return res.status(503).json({ error: 'OTX no configurado' });
  if (Date.now() - otxCache.lastFetch > OTX_CACHE_TTL) await refreshOTXData();

  const counts = {};
  otxCache.pulses.forEach(p => {
    if (p.adversary) {
      counts[p.adversary] = (counts[p.adversary] || 0) + 1;
    }
  });

  const sorted = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({ name, count }));

  res.json({ success: true, adversaries: sorted, cachedAt: otxCache.lastFetch });
});

app.get('/api/otx/industries', async (req, res) => {
  if (!OTX_API_KEY) return res.status(503).json({ error: 'OTX no configurado' });
  if (Date.now() - otxCache.lastFetch > OTX_CACHE_TTL) await refreshOTXData();

  const { source } = req.query;
  const counts = {};
  
  otxCache.pulses.forEach(p => {
    if (source && source !== 'TODOS' && p.source !== source) return;
    
    (p.industries || []).forEach(ind => {
      counts[ind] = (counts[ind] || 0) + 1;
    });
  });

  const sorted = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({ name, count }));

  res.json({ success: true, industries: sorted, cachedAt: otxCache.lastFetch });
});

app.post('/api/otx/refresh', async (req, res) => {
  if (!OTX_API_KEY) return res.status(503).json({ error: 'OTX no configurado' });
  await refreshOTXData();
  res.json({ success: true, pulses: otxCache.pulses.length, indicators: otxCache.indicators.length });
});

// ─── AUTENTICACIÓN DEL CANAL DE SENSORES ─────────────────────────────────────
// El token va en el cuerpo porque así lo envía el agente. Se compara en tiempo
// constante para no filtrar el prefijo correcto a través del tiempo de respuesta.
const AGENT_TOKEN = process.env.AGENT_TOKEN || '';

if (!AGENT_TOKEN) {
  console.warn('\n⚠️  AGENT_TOKEN no está definido en .env — el canal de sensores queda CERRADO.');
  console.warn('   Genera uno con:  node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  console.warn('   y ponlo en .env (servidor) y en agent/agent.config.json (sensores).\n');
} else if (AGENT_TOKEN === 'DEFAULT_TOKEN') {
  console.warn('\n⚠️  AGENT_TOKEN tiene el valor de ejemplo "DEFAULT_TOKEN": cualquiera en la red puede');
  console.warn('   inyectar telemetría falsa. Reemplázalo por un valor aleatorio.\n');
}

function tokenIsValid(received) {
  // Sin token configurado se falla cerrado: es preferible que los sensores dejen
  // de reportar (visible en el dashboard) a aceptar un secreto por defecto conocido.
  if (!AGENT_TOKEN) return false;
  if (typeof received !== 'string' || received.length === 0) return false;
  const a = Buffer.from(received);
  const b = Buffer.from(AGENT_TOKEN);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function requireAgentToken(req, res, next) {
  if (!tokenIsValid(req.body && req.body.token)) {
    console.warn(`[AUTH] ⛔ Rechazada petición de sensor sin token válido: ${req.method} ${req.path} desde ${req.ip}`);
    return res.status(403).json({ error: 'Token de agente inválido o ausente' });
  }
  next();
}

// ─── ENDPOINTS SENSORES INTERNOS ──────────────────────────────────────────────
app.post('/api/sensors/report', requireAgentToken, (req, res) => {
  const { agent_id, hostname, ip, event, severity } = req.body;

  const query = `INSERT INTO sensor_alerts (agent_id, hostname, ip, event, severity) VALUES (?, ?, ?, ?, ?)`;
  db.run(query, [agent_id || 'unknown', hostname || 'unknown', ip || 'unknown', event || 'unknown event', severity || 'INFO'], function(err) {
    if (err) {
      console.error('[SQLite] Error al insertar alerta de sensor:', err.message);
      return res.status(500).json({ error: 'Error interno guardando la alerta' });
    }
    console.log(`[SENSOR] Alerta recibida de ${hostname || ip}: ${event}`);
    res.json({ success: true, alertId: this.lastID });
  });
});

app.get('/api/sensors/events', (req, res) => {
  db.all(`SELECT * FROM sensor_alerts ORDER BY timestamp DESC LIMIT 100`, [], (err, rows) => {
    if (err) {
      console.error('[SQLite] Error leyendo alertas de sensores:', err.message);
      return res.status(500).json({ error: 'Error leyendo datos de sensores' });
    }
    res.json({ success: true, events: rows });
  });
});

app.post('/api/sensors/heartbeat', requireAgentToken, (req, res) => {
  const { agent_id, hostname, ip } = req.body;

  const query = `
    INSERT INTO sensor_endpoints (agent_id, hostname, ip, status, last_seen)
    VALUES (?, ?, ?, 'ONLINE', CURRENT_TIMESTAMP)
    ON CONFLICT(agent_id) DO UPDATE SET
      hostname=excluded.hostname,
      ip=excluded.ip,
      status='ONLINE',
      last_seen=CURRENT_TIMESTAMP
  `;
  db.run(query, [agent_id || 'unknown', hostname || 'unknown', ip || 'unknown'], function(err) {
    if (err) {
      console.error('[SQLite] Error en heartbeat:', err.message);
      return res.status(500).json({ error: 'Error interno en heartbeat' });
    }
    res.json({ success: true });
  });
});

app.post('/api/sensors/sysinfo', requireAgentToken, (req, res) => {
  const { agent_id, hardware, software } = req.body;
  const hwJson = JSON.stringify(hardware || {});
  const swJson = JSON.stringify(software || []);
  db.run(`UPDATE sensor_endpoints SET hardware_info=?, software_info=?, status='ONLINE', last_seen=CURRENT_TIMESTAMP WHERE agent_id=?`, [hwJson, swJson, agent_id], function(err) {
    if (err) {
      console.error('[SQLite] Error guardando sysinfo:', err.message);
      return res.status(500).json({ error: 'Error guardando sysinfo' });
    }
    
    // Buscar el hostname para un log más descriptivo
    db.get(`SELECT hostname FROM sensor_endpoints WHERE agent_id = ?`, [agent_id], (err, row) => {
      const hName = row ? row.hostname : agent_id;
      console.log(`\x1b[33m[SYSINFO]\x1b[0m Info de sistema recibida de \x1b[36msensor_win_${hName}\x1b[0m`);
    });

    res.json({ success: true });
  });
});

app.get('/api/sensors/endpoints', (req, res) => {
  db.all(`SELECT * FROM sensor_endpoints ORDER BY last_seen DESC`, [], (err, rows) => {
    if (err) {
      console.error('[SQLite] Error leyendo endpoints:', err.message);
      return res.status(500).json({ error: 'Error leyendo endpoints' });
    }
    
    const now = new Date();
    const updatedRows = rows.map(r => {
      const lastSeen = new Date(r.last_seen + "Z");
      const diffMins = (now - lastSeen) / 1000 / 60;
      if (diffMins > 15 && r.status === 'ONLINE') {
        r.status = 'OFFLINE';
        db.run(`UPDATE sensor_endpoints SET status='OFFLINE' WHERE agent_id=?`, [r.agent_id]);
      }
      return r;
    });
    res.json({ success: true, endpoints: updatedRows });
  });
});

app.delete('/api/sensors/endpoints/:agent_id', (req, res) => {
  const { agent_id } = req.params;
  db.run(`DELETE FROM sensor_endpoints WHERE agent_id = ?`, [agent_id], function(err) {
    if (err) {
      console.error('[SQLite] Error eliminando endpoint:', err.message);
      return res.status(500).json({ error: 'Error interno eliminando el endpoint' });
    }
    res.json({ success: true });
  });
});

app.post('/api/sensors/force-reconnect/:agent_id', (req, res) => {
  const { agent_id } = req.params;
  db.run(`UPDATE sensor_endpoints SET status='PENDING RECONNECT' WHERE agent_id=?`, [agent_id], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Error interno' });
    }
    res.json({ success: true, message: 'Señal de reconexión forzada encolada. El agente se conectará dentro de 60 segundos o menos.' });
  });
});

app.post('/api/sensors/check/:agent_id', requireAgentToken, (req, res) => {
  const { agent_id } = req.params;
  // Actualizar last_seen y status a ONLINE cada vez que el agente consulte comandos
  db.run(`UPDATE sensor_endpoints SET status='ONLINE', last_seen=CURRENT_TIMESTAMP WHERE agent_id=?`, [agent_id]);

  db.get(`SELECT status FROM sensor_endpoints WHERE agent_id = ?`, [agent_id], (err, row) => {
    if (err || !row) return res.json({ force: false });
    
    if (row.status === 'PENDING RECONNECT') {
      // Una vez detectado, reseteamos a ONLINE para que no se repita el bucle
      db.run(`UPDATE sensor_endpoints SET status='ONLINE' WHERE agent_id=?`, [agent_id]);
      res.json({ force: true });
    } else {
      res.json({ force: false });
    }
  });
});

// ─── SCORING DE COMPORTAMIENTO ────────────────────────────────────────────────
// El score es una ventana de riesgo reciente, no un contador histórico: decae con
// el tiempo, así un endpoint que deja de generar eventos vuelve solo a 'low' en
// lugar de quedarse anclado en 'critical' hasta un reset manual.
const BEHAVIOR_DECAY_PER_HOUR = 5;
const BEHAVIOR_MAX_SCORE = 100;

// Score tras aplicar el decaimiento acumulado desde last_update (nunca baja de 0).
// COALESCE cubre las filas creadas antes de que existiera la columna: en su primer
// recálculo decaen 0 y a partir de ahí ya tienen base temporal.
const BEHAVIOR_DECAYED_SCORE_SQL = `MAX(0, current_score - CAST(
  (julianday('now') - julianday(COALESCE(last_update, CURRENT_TIMESTAMP))) * 24 * ${BEHAVIOR_DECAY_PER_HOUR} AS INTEGER))`;

const BEHAVIOR_STATUS_SQL = `CASE
  WHEN current_score >= 80 THEN 'critical'
  WHEN current_score >= 60 THEN 'high'
  WHEN current_score >= 30 THEN 'suspicious'
  ELSE 'low'
END`;

/**
 * Aplica el decaimiento pendiente a un agente y le suma riesgo nuevo.
 * Con addRisk = 0 sirve como "refrescar antes de leer": las vistas ven el score
 * decaído aunque el agente lleve días sin reportar.
 */
function refreshBehaviorScore(agent_id, addRisk = 0, done = () => {}) {
  const delta = Math.max(0, Math.min(addRisk, BEHAVIOR_MAX_SCORE));
  db.run(
    `INSERT INTO sensor_behavior_scores (agent_id, current_score, last_update, last_alert_timestamp)
     VALUES (?, ?, CURRENT_TIMESTAMP, CASE WHEN ? > 0 THEN CURRENT_TIMESTAMP ELSE NULL END)
     ON CONFLICT(agent_id) DO UPDATE SET
       current_score = MIN(${BEHAVIOR_DECAYED_SCORE_SQL} + excluded.current_score, ${BEHAVIOR_MAX_SCORE}),
       last_update = CURRENT_TIMESTAMP,
       last_alert_timestamp = CASE WHEN excluded.current_score > 0
         THEN CURRENT_TIMESTAMP ELSE last_alert_timestamp END`,
    [agent_id, delta, delta],
    (err) => {
      if (err) return done(err);
      // El estado se deriva siempre del score ya persistido, así la rama de INSERT
      // y la de UPDATE no pueden divergir.
      db.run(`UPDATE sensor_behavior_scores SET status = ${BEHAVIOR_STATUS_SQL} WHERE agent_id = ?`, [agent_id], done);
    }
  );
}

/** Igual que refreshBehaviorScore pero para todos los agentes (vistas agregadas). */
function refreshAllBehaviorScores(done = () => {}) {
  db.run(
    `UPDATE sensor_behavior_scores SET current_score = ${BEHAVIOR_DECAYED_SCORE_SQL}, last_update = CURRENT_TIMESTAMP`,
    (err) => {
      if (err) return done(err);
      db.run(`UPDATE sensor_behavior_scores SET status = ${BEHAVIOR_STATUS_SQL}`, done);
    }
  );
}

// ─── ENDPOINTS TELEMETRÍA Y DETECCIONES (EDR) ──────────────────────────────────
app.post('/api/sensors/telemetry', requireAgentToken, (req, res) => {
  const { agent_id, events } = req.body;

  if (!events || !Array.isArray(events)) return res.status(400).json({ error: 'Formato inválido' });

  const stmt = db.prepare(`INSERT INTO sensor_telemetry 
    (agent_id, event_type, process_name, parent_process, target_path, dst_ip, dst_domain, risk_score, mitre_id, mitre_tactic, mitre_technique, severity, raw_json) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);

  // Buffer en memoria para telemetría volátil (INFO)
  global.volatileTelemetry = global.volatileTelemetry || {};

  // Riesgo del lote. Se acumula dentro del loop para que incluya el enriquecimiento
  // de OTX (+50 por match), que es lo que se perdía al recalcularlo aparte.
  let totalRisk = 0;

  events.forEach(ev => {
    let extraRisk = 0;
    let intelMatch = null;

    if (OTX_API_KEY && otxCache.indicators.length > 0) {
      if (ev.dst_ip) intelMatch = otxCache.indicators.find(i => i.indicator === ev.dst_ip && i.type === 'IPv4');
      if (!intelMatch && ev.file_hash) intelMatch = otxCache.indicators.find(i => i.indicator.toLowerCase() === ev.file_hash.toLowerCase());

      if (intelMatch) {
        extraRisk = 50;
        db.run(`INSERT INTO sensor_detections (agent_id, detection_type, severity, score, details, behavior_chain) 
                VALUES (?, ?, ?, ?, ?, ?)`, 
                [agent_id, 'THREAT_INTEL_MATCH', 'CRITICAL', 50, 
                 `Coincidencia OTX: ${intelMatch.pulse_name}. Indicador: ${intelMatch.indicator}`, 
                 JSON.stringify(ev)]);
      }
    }

    const finalRisk = (ev.risk_score || 0) + extraRisk;
    totalRisk += finalRisk;
    const enrichedEvent = {...ev, intel_match: intelMatch ? intelMatch.pulse_name : null, timestamp: ev.timestamp || new Date().toISOString()};

    if (finalRisk >= 30) {
      // PERSISTENTE: Guardar en DB porque hay riesgo relevante (Medio, Alto o Crítico)
      stmt.run([
        agent_id, ev.type, ev.process_name || null, null, ev.target_path || null, 
        ev.dst_ip || null, null, finalRisk,
        ev.mitre_id || null, ev.mitre_tactic || null, ev.mitre_technique || null, ev.severity || 'LOW',
        JSON.stringify(enrichedEvent)
      ]);
    } else {
      // VOLÁTIL: Guardar solo en RAM para el timeline actual
      if (!global.volatileTelemetry[agent_id]) global.volatileTelemetry[agent_id] = [];
      global.volatileTelemetry[agent_id].unshift(enrichedEvent);
      // Mantener los últimos 50 eventos para mayor fluidez en tiempo real
      if (global.volatileTelemetry[agent_id].length > 50) global.volatileTelemetry[agent_id].pop();
    }
  });
  stmt.finalize();

  // Tarea de limpieza: Borrar telemetría vieja (> 30 días) cada 24 horas
  const cleanupTelemetry = () => {
    db.run("DELETE FROM sensor_telemetry WHERE timestamp < datetime('now', '-30 days')", (err) => {
      if (!err) console.log("[DB] Limpieza de telemetría (30 días) completada.");
    });
  };
  if (!global.cleanupIntervalSet) {
    setInterval(cleanupTelemetry, 24 * 60 * 60 * 1000);
    global.cleanupIntervalSet = true;
  }

  // Actualizar Score acumulado si aplica
  if (totalRisk > 0) {
    refreshBehaviorScore(agent_id, totalRisk, (err) => {
      if (err) console.error('[EDR] Error actualizando behavior score:', err.message);
    });
  }

  res.json({ success: true, count: events.length });
});

app.post('/api/sensors/detection', requireAgentToken, (req, res) => {
  const { agent_id, type, severity, score, details, chain } = req.body;

  db.run(`INSERT INTO sensor_detections (agent_id, detection_type, severity, score, details, behavior_chain)
          VALUES (?, ?, ?, ?, ?, ?)`,
          [agent_id, type, severity, score, details, JSON.stringify(chain)]);

  // La detección suma al score y el estado se deriva de ahí. Escribir `status`
  // directamente desde `severity` metía valores fuera del vocabulario
  // (low/suspicious/high/critical) y desincronizaba estado y puntaje.
  refreshBehaviorScore(agent_id, Number(score) || 0, (err) => {
    if (err) console.error('[EDR] Error actualizando behavior score:', err.message);
  });

  res.json({ success: true });
});

app.get('/api/sensors/behavior/:agent_id', (req, res) => {
  const { agent_id } = req.params;
  // Refrescar antes de leer: el score mostrado incluye el decaimiento acumulado
  // desde el último evento, aunque el agente lleve días offline.
  refreshBehaviorScore(agent_id, 0, () => {
    db.get(`SELECT * FROM sensor_behavior_scores WHERE agent_id = ?`, [agent_id], (err, score) => {
      db.all(`SELECT * FROM sensor_detections WHERE agent_id = ? ORDER BY timestamp DESC LIMIT 10`, [agent_id], (err, detections) => {
        db.all(`SELECT * FROM sensor_telemetry WHERE agent_id = ? ORDER BY timestamp DESC LIMIT 50`, [agent_id], (err, telemetry) => {

          // Unir telemetría persistente con la volátil de la RAM
          const volatile = (global.volatileTelemetry && global.volatileTelemetry[agent_id]) || [];

          // Mapear los resultados de la DB (raw_json) a objetos
          const persistent = (telemetry || []).map(t => {
            try {
              const parsed = JSON.parse(t.raw_json);
              // Si el timestamp de la DB no tiene 'Z', se lo añadimos para que JS sepa que es UTC
              let ts = t.timestamp || parsed.timestamp;
              if (ts && !ts.endsWith('Z')) ts += 'Z';
              return { ...parsed, timestamp: ts };
            } catch(e) { return t; }
          });

          // Combinar, filtrar duplicados por timestamp y ordenar
          const combinedTelemetry = [...volatile, ...persistent]
            .filter(ev => ev && ev.timestamp)
            .sort((a, b) => {
              const dateA = new Date(a.timestamp);
              const dateB = new Date(b.timestamp);
              return (dateB - dateA) || 0;
            })
            .slice(0, 50);

          res.json({
            success: true,
            score: score || { current_score: 0, status: 'low' },
            detections: detections || [],
            telemetry: combinedTelemetry
          });
        });
      });
    });
  });
});

app.get('/api/sensors/analysis/summary', (req, res) => {
  const summary = {
    counts: { suspicious: 0, high: 0, critical: 0 },
    top_threats: [],
    recent_detections: [],
    top_endpoints: []
  };

  // 0. Aplicar el decaimiento pendiente a todos los agentes, para que los
  //    contadores no muestren endpoints anclados en 'critical' desde hace días.
  refreshAllBehaviorScores(() => {

    // 1. Contadores por severidad
    db.all(`SELECT status, COUNT(*) as count FROM sensor_behavior_scores GROUP BY status`, (err, rows) => {
      rows?.forEach(r => { if (summary.counts[r.status] !== undefined) summary.counts[r.status] = r.count; });

      // 2. Últimas detecciones críticas (EDR)
      db.all(`SELECT d.*, s.hostname
              FROM sensor_detections d
              JOIN sensor_endpoints s ON d.agent_id = s.agent_id
              ORDER BY d.timestamp DESC LIMIT 10`, (err, detections) => {
        summary.recent_detections = detections || [];

        // 3. Equipos con más riesgo
        db.all(`SELECT hostname, current_score, status
                FROM sensor_behavior_scores b
                JOIN sensor_endpoints s ON b.agent_id = s.agent_id
                WHERE current_score > 0
                ORDER BY current_score DESC LIMIT 5`, (err, endpoints) => {
          summary.top_endpoints = endpoints || [];

          // 4. Tipos de amenazas más comunes
          db.all(`SELECT event_type, COUNT(*) as count
                  FROM sensor_telemetry
                  WHERE risk_score > 0
                  GROUP BY event_type ORDER BY count DESC LIMIT 5`, (err, threats) => {
            summary.top_threats = threats || [];
            res.json({ success: true, ...summary });
          });
        });
      });
    });
  });
});

// ─── WEBHOOKS EXTERNOS (APIFY / OTROS) ───────────────────────────────────────

/**
 * Endpoint para recibir resultados de Apify Brand Protection Monitor vía Webhook.
 * Configuración en Apify: 
 * URL: https://TU_URL_PUBLICA/api/webhooks/apify/brand-monitor?domain=tu-dominio.com
 * Method: POST
 * Content-Type: application/json
 */
app.post('/api/webhooks/apify/brand-monitor', async (req, res) => {
  const { domain } = req.query;
  const payload = req.body;

  if (!domain) return res.status(400).json({ error: 'Falta el parámetro domain en la URL' });

  const asset = localAssets.find(a => a.domain === domain);
  if (!asset) {
    console.log(`[WEBHOOK] Recibidos datos para un dominio no monitoreado: ${domain}`);
    return res.status(404).json({ error: 'Dominio no encontrado en Assets' });
  }

  console.log(`[WEBHOOK] 📥 Procesando señal de Brand Protection para: ${domain}`);
  console.log(`[WEBHOOK] Estructura recibida:`, JSON.stringify(Object.keys(payload)));
  console.log(`[WEBHOOK] Contenido de resource:`, JSON.stringify(payload.resource));

  try {
    let items = [];
    
    // Buscar el ID del dataset en varios lugares posibles (Apify cambia según el evento)
    const datasetId = payload.resource?.defaultDatasetId || payload.eventData?.defaultDatasetId || payload.defaultDatasetId;

    if (datasetId) {
      console.log(`[WEBHOOK] 📡 Descargando items desde Dataset Apify: ${datasetId}`);
      const datasetResults = await apifyClient.dataset(datasetId).listItems();
      items = datasetResults.items;
    } 
    else if (payload.resource?.id && payload.eventType?.includes('RUN')) {
      // Si no hay datasetId directo, probar con el ID del Run para obtener su dataset
      console.log(`[WEBHOOK] 📡 Obteniendo dataset desde Run ID: ${payload.resource.id}`);
      const run = await apifyClient.run(payload.resource.id).get();
      if (run && run.defaultDatasetId) {
        const datasetResults = await apifyClient.dataset(run.defaultDatasetId).listItems();
        items = datasetResults.items;
      }
    }
    // Caso C: Los datos vienen directamente (Manual/Test)
    else {
      items = Array.isArray(payload) ? payload : (payload.items || payload.data || []);
    }

    if (items.length === 0) {
      console.log(`[WEBHOOK] El escaneo para ${domain} no devolvió hallazgos.`);
      return res.json({ success: true, message: 'Escaneo vacío procesado' });
    }

    const processedResults = [];
    let newFindingsCount = 0;

    // Aplanamos los resultados de las diferentes categorías del actor (Estrategia Pro)
    const rawItems = [];
    items.forEach(doc => {
      if (doc.typosquatDomains) {
        doc.typosquatDomains.forEach(item => {
          rawItems.push({ ...item, type: 'Typosquatting', url: item.domainUrl || item.domain });
        });
      }
      if (doc.socialMediaProfiles) {
        doc.socialMediaProfiles.forEach(item => {
          rawItems.push({ ...item, type: 'Social Media', url: item.url });
        });
      }
      if (doc.webMentions) {
        doc.webMentions.forEach(item => {
          rawItems.push({ ...item, type: 'Web Mention', url: item.url });
        });
      }
    });

    for (const item of rawItems) {
      const url = item.url || '';
      if (!url) continue;

      const result = {
        title: item.title || item.domain || item.handle || 'Detección Brand Protection',
        url: url.startsWith('http') ? url : `http://${url}`,
        description: item.description || `Detectado en ${item.platform || item.type}`,
        likes: item.engagement || item.followers || null,
        type: item.type || 'apify_monitor',
        verified: item.isVerified || item.verified || false,
        status: item.status || (item.dnsValid ? 'active' : 'inactive'),
        isResolving: item.dnsValid || item.isResolving || false,
        riskLevel: item.riskLevel || item.riskScore || 'N/A'
      };

      const isDuplicate = await new Promise((resolve) => {
        db.get('SELECT id FROM brand_protection_findings WHERE finding_url = ?', [url], (err, row) => {
          resolve(!!row);
        });
      });

      if (!isDuplicate) {
        newFindingsCount++;
        result.isNew = true;
        db.run(
          `INSERT INTO brand_protection_findings (domain, finding_url, title, description, source, severity) VALUES (?, ?, ?, ?, ?, ?)`,
          [domain, url, result.title, result.description, 'APIFY_WEBHOOK', result.riskLevel]
        );
      } else {
        result.isNew = false;
      }

      processedResults.push(result);
    }

    asset.fbScraperCache = {
      results: processedResults,
      cachedAt: new Date().toISOString(),
      domain: asset.domain,
      source: 'APIFY_WEBHOOK',
      newFindings: newFindingsCount
    };

    saveAssets();
    
    console.log(`[WEBHOOK] ✓ Proceso completado para ${domain}. Hallazgos totales: ${processedResults.length}, Nuevos: ${newFindingsCount}`);
    
    res.json({ success: true, newFindings: newFindingsCount, totalProcessed: processedResults.length });

  } catch (err) {
    console.error('[WEBHOOK] Error crítico:', err.message);
    res.status(500).json({ error: 'Error interno' });
  }
});

// ─── INICIAR SERVIDOR HTTPS PARA SENSORES ────────────────────────────────────
try {
  const privateKey = fs.readFileSync(path.join(__dirname, 'server.key'), 'utf8');
  const certificate = fs.readFileSync(path.join(__dirname, 'server.cert'), 'utf8');
  const credentials = { key: privateKey, cert: certificate };

  const httpsServer = https.createServer(credentials, app);
  httpsServer.listen(HTTPS_PORT, () => {
    console.log(`🔒 Servidor HTTPS (Sensores) corriendo en: https://0.0.0.0:${HTTPS_PORT}`);
  });
} catch (err) {
  console.log('⚠️ No se encontraron certificados SSL (server.key / server.cert). El puerto HTTPS 8443 no fue iniciado.');
}

// ─── INICIAR SERVIDOR ─────────────────────────────────────────────────────────
// Escucha sólo en loopback: la API del dashboard no tiene autenticación, así que
// no debe estar accesible desde la red. Los sensores usan el canal HTTPS :8443.
const PORT = 3001;
app.listen(PORT, '127.0.0.1', () => {
  console.log('\n🛡️  CyberIntel EC — Servidor RSS local (Con Histórico)');
  console.log(`📡 Corriendo en: http://127.0.0.1:${PORT} (sólo local)`);
});
