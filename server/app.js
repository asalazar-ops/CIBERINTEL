// ─────────────────────────────────────────────────────────────────────────────
// CyberIntel EC — App Express (feeds, assets, OTX, EDR, auth).
// Este módulo solo CONSTRUYE y EXPORTA la app: no abre ningún puerto. Eso es
// responsabilidad de quien lo importe — server.js (arranque local con doble
// puerto HTTP/HTTPS) o api/index.js (entrypoint serverless de Vercel, un solo
// handler por invocación). Separar ambas cosas es lo que hace que la misma
// lógica de negocio sirva a los dos entornos sin duplicarse.
// ─────────────────────────────────────────────────────────────────────────────

// Debe cargarse antes que cualquier require local que lea process.env al nivel
// superior del módulo (p. ej. auth.js valida AUTH_SECRET al importarse). En
// Vercel las variables de entorno ya están inyectadas por la plataforma, pero
// dotenv.config() no falla si no encuentra un .env — sigue siendo seguro.
require('dotenv').config();

const express   = require('express');
const cors      = require('cors');
const Parser    = require('rss-parser');
const fs        = require('fs');
const path      = require('path');
const dns       = require('dns').promises;
const https     = require('https');
const crypto    = require('crypto');
const cookieParser = require('cookie-parser');
const archiver = require('archiver');
const { verifyCredentials, issueSessionCookie, clearSessionCookie, readSession, requireAuth } = require('./auth');
const dbLayer = require('./db');
const { articles: articlesStore, assets: assetsStore, otxCache: otxCacheStore, cronRuns } = require('./store');
const { ApifyClient } = require('apify-client');
const intelSources = require('./intel/sources');
const intelIngest = require('./intel/ingest');
const intelLookup = require('./intel/lookup');
const vulnDictionary = require('./vuln/dictionary');
const vulnCatalog = require('./vuln/catalog');
const vulnCorrelate = require('./vuln/correlate');

// ─── BASE DE DATOS (Turso/libSQL) ────────────────────────────────────────────
// `db` conserva la firma callback-style de sqlite3 (run/get/all/prepare) para
// que las rutas EDR de más abajo no necesiten reescribirse — ver el shim de
// compatibilidad en server/db.js. El motor real es asíncrono (Turso remoto o
// un archivo local embebido si no hay TURSO_DATABASE_URL) y ya no depende del
// binario nativo de sqlite3, que no corre en funciones serverless.
const db = dbLayer.legacy;
dbLayer.initSchema()
  .then(() => {
    console.log('[DB] Esquema listo (Turso/libSQL).');
    return vulnDictionary.seedDictionary();
  })
  .catch((err) => console.error('[DB] Error inicializando el esquema:', err.message));

const apifyClient = new ApifyClient({ token: process.env.APIFY_TOKEN });

// APIFY_WEBHOOK_SECRET: valida que las llamadas a /api/webhooks/apify/brand-monitor
// vengan realmente de Apify (falla cerrado si no está configurado, ver más abajo).
// APIFY_WEBHOOK_URL: dominio público de este despliegue (ej. https://tu-app.vercel.app)
// — se le pasa a Apify al disparar el run con .start() para que sepa a dónde
// devolver el resultado. Sin esto, /api/assets/fb-scraper/:id no puede iniciar
// escaneos asíncronos porque Apify no tendría dónde entregarlos.
const APIFY_WEBHOOK_SECRET = process.env.APIFY_WEBHOOK_SECRET || '';
const APIFY_WEBHOOK_URL = process.env.APIFY_WEBHOOK_URL || '';
if (!APIFY_WEBHOOK_SECRET) {
  console.warn('\n⚠️  APIFY_WEBHOOK_SECRET no está definido — el webhook de Apify queda CERRADO.');
  console.warn('   Sin esto, cualquiera en internet podría inyectar hallazgos falsos de brand protection.\n');
}
if (!APIFY_WEBHOOK_URL) {
  console.warn('\n⚠️  APIFY_WEBHOOK_URL no está definida — los escaneos asíncronos de Brand Protection');
  console.warn('   (POST /api/assets/fb-scraper/:id) quedan deshabilitados hasta configurarla.\n');
}

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

// CORS_ORIGIN permite fijar el dominio real en producción (Vercel es same-origin,
// pero el valor por defecto mantiene el flujo de desarrollo local intacto).
app.use(cors({ origin: process.env.CORS_ORIGIN || 'http://localhost:5173', credentials: true }));
app.use(express.json());
app.use(cookieParser());

// ─── CANAL DE SENSORES: rutas que autentica el agente con su propio token ────
// Se define aquí (antes de los dos filtros que la usan) porque tanto el
// aislamiento por puerto como el middleware de sesión necesitan coincidir
// exactamente: cualquier otra ruta bajo /api/sensors/* (endpoints, behavior,
// analysis/summary, force-reconnect, delete) es gestión del dashboard, no del
// agente, y debe exigir sesión igual que el resto de la API.
const SENSOR_CHANNEL_PATHS = [
  '/api/sensors/heartbeat',
  '/api/sensors/sysinfo',
  '/api/sensors/telemetry',
  '/api/sensors/detection',
];
const isSensorChannelPath = (p) => SENSOR_CHANNEL_PATHS.includes(p) || p.startsWith('/api/sensors/check/');

// ─── AUTENTICACIÓN DEL DASHBOARD ─────────────────────────────────────────────
// Sin usuario ni contraseña, la API de gestión queda accesible a cualquiera con
// la URL: inventario de assets de clientes, inventario HW/SW de endpoints,
// hallazgos de brand protection, y acciones destructivas (borrar endpoints) o
// con costo (disparar Apify). Lista blanca explícita en vez de decorar cada ruta
// una por una, para que una ruta nueva no quede desprotegida por omisión.
//
// OJO: no basta con eximir todo `/api/sensors/*` — GET endpoints/events/behavior,
// analysis/summary, DELETE endpoints y force-reconnect son rutas de GESTIÓN que
// viven bajo ese prefijo pero no llevan requireAgentToken; deben exigir sesión.
const PUBLIC_API_PATHS = [
  '/api/auth/login',
  '/api/auth/logout', // debe funcionar incluso con la sesión ya vencida
  '/api/auth/me',     // responde 401 explícito en vez de heredar el genérico del middleware
  '/api/webhooks/apify/brand-monitor',
];

app.use((req, res, next) => {
  if (!req.path.startsWith('/api/')) return next();
  if (isSensorChannelPath(req.path)) return next(); // usa requireAgentToken
  if (PUBLIC_API_PATHS.includes(req.path)) return next();
  return requireAuth(req, res, next);
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const ok = await verifyCredentials(email, password);
  if (!ok) return res.status(401).json({ error: 'Credenciales inválidas' });
  issueSessionCookie(res, email.trim().toLowerCase());
  res.json({ success: true, email: email.trim().toLowerCase() });
});

app.post('/api/auth/logout', (req, res) => {
  clearSessionCookie(res);
  res.json({ success: true });
});

app.get('/api/auth/me', (req, res) => {
  const session = readSession(req);
  if (!session) return res.status(401).json({ error: 'Sin sesión' });
  res.json({ success: true, email: session.sub });
});

// ─── AISLAMIENTO DE CANALES (solo aplica en modo local) ──────────────────────
// En desarrollo local, server.js abre la misma app en dos puertos: 3001
// (dashboard, sólo loopback) y 8443 (sensores, expuesto a la LAN). Sin este
// filtro, el puerto de sensores también serviría la API de gestión — incluido
// DELETE de endpoints y los recon de Apify — a cualquiera en la red.
//
// En Vercel no existe el puerto 8443 (todo entra por :443), así que
// req.socket.localPort nunca vale HTTPS_PORT y este bloque nunca se activa —
// inofensivo dejarlo. El aislamiento real, válido en ambos entornos, lo dan
// requireAuth (rutas de gestión) y requireAgentToken (rutas de sensor).
const HTTPS_PORT = 8443;

app.use((req, res, next) => {
  if (req.socket.localPort !== HTTPS_PORT) return next();
  if (isSensorChannelPath(req.path)) return next();

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

// Los artículos ya no se cargan en un array en memoria al arrancar: cada ruta
// consulta articlesStore (Turso) directamente. La re-clasificación de datos
// legacy que corría aquí fue un one-off ya aplicado antes de migrar a Turso
// (ver server/migrate_to_turso.js) — los artículos migrados ya llevan sector,
// severity y region correctos.

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

/**
 * Escanea TODOS los assets en secuencia. Cada scanDomain() puede tardar más de
 * 20s por sí solo (crt.sh, cientos de variantes de typosquatting) — con 6+
 * dominios esto fácilmente supera el límite de duración de una función
 * serverless. Solo se usa en modo local (setInterval de abajo); el cron de
 * Vercel usa autoScanNextAsset(), que hace uno por invocación.
 */
async function autoScanAssets() {
  const currentAssets = await assetsStore.listAll();
  if (currentAssets.length === 0) return;
  console.log(`[MONITOR] Iniciando escaneo automático de ${currentAssets.length} assets...`);
  for (const asset of currentAssets) {
    try {
      // Pasar subdominios actuales para no perderlos si una fuente falla temporalmente
      const result = await scanDomain(asset.domain, asset.subdomains || []);
      await assetsStore.updateScanResult(asset.id, result);
      console.log(`  ✓ ${asset.domain} actualizado automáticamente.`);
    } catch (err) {
      console.error(`  ✗ Error en auto-escaneo de ${asset.domain}:`, err.message);
    }
  }
}

/**
 * Escanea solo el asset menos recientemente escaneado (o sin escanear:
 * last_scan NULL primero) y devuelve cuál tocó, o null si no hay assets.
 * Pensada para que el cron de Vercel (cada 6h) rote por todos los dominios
 * sin arriesgar el límite de duración de una sola invocación.
 */
async function autoScanNextAsset() {
  const currentAssets = await assetsStore.listAll();
  if (currentAssets.length === 0) return null;

  const next = [...currentAssets].sort((a, b) => {
    const ta = a.lastScan ? new Date(a.lastScan).getTime() : 0;
    const tb = b.lastScan ? new Date(b.lastScan).getTime() : 0;
    return ta - tb; // más antiguo (o nunca escaneado) primero
  })[0];

  console.log(`[CRON] Escaneando asset: ${next.domain} (último escaneo: ${next.lastScan || 'nunca'})`);
  const result = await scanDomain(next.domain, next.subdomains || []);
  await assetsStore.updateScanResult(next.id, result);
  return next.domain;
}

/**
 * Escanea assets en orden "más antiguo/nunca escaneado primero" hasta agotar
 * maxMs de presupuesto, no una cantidad fija — el plan Hobby de Vercel limita
 * la duración de función y solo permite crons diarios, así que esta única
 * invocación diaria debe cubrir tantos assets como el tiempo permita; los que
 * no alcancen quedan primeros en la cola de la corrida siguiente por el mismo
 * criterio de ordenamiento que autoScanNextAsset().
 */
async function autoScanAssetsBudgeted(maxMs) {
  const currentAssets = await assetsStore.listAll();
  const ordered = [...currentAssets].sort((a, b) => {
    const ta = a.lastScan ? new Date(a.lastScan).getTime() : 0;
    const tb = b.lastScan ? new Date(b.lastScan).getTime() : 0;
    return ta - tb;
  });

  const started = Date.now();
  const scanned = [];
  for (const asset of ordered) {
    if (Date.now() - started > maxMs) break;
    try {
      const result = await scanDomain(asset.domain, asset.subdomains || []);
      await assetsStore.updateScanResult(asset.id, result);
      scanned.push(asset.domain);
    } catch (err) {
      console.error(`  ✗ Error en auto-escaneo de ${asset.domain}:`, err.message);
    }
  }
  return { scanned, pending: ordered.length - scanned.length };
}

// Monitoreo automático cada 6 horas — SOLO en modo local (node server.js).
// setInterval no sobrevive entre invocaciones serverless (cada una es un
// proceso nuevo que muere al responder); en Vercel (donde la plataforma
// define VERCEL=1) el mismo trabajo lo dispara el cron /api/cron/scan-assets.
if (!process.env.VERCEL) {
  setInterval(autoScanAssets, 6 * 60 * 60 * 1000);
}

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

// Antes, GET /api/feeds hacía el fetch de las 15 fuentes RSS dentro de la
// misma petición que atendía al dashboard: el usuario esperaba al feed más
// lento, y en serverless eso arriesga el límite de duración de la función.
// Ahora ese trabajo lo hace el cron /api/cron/refresh-feeds (ver más abajo);
// esta función queda expuesta para que el cron la reutilice sin duplicar
// lógica, y GET /api/feeds pasa a ser solo lectura de lo que ya está en Turso.
async function refreshAllFeeds() {
  const feedStatus = {};

  // INSERT...ON CONFLICT DO NOTHING (unique_id) reemplaza el
  // localData.some(...) + push(): una sola sentencia atómica por artículo en
  // vez de comprobar duplicado y mutar un array compartido — la única forma
  // segura de hacerlo cuando dos invocaciones pueden correr a la vez.
  await Promise.all(FEEDS.map(async (feed) => {
    try {
      const parsed = await parser.parseURL(feed.url);
      const items = parsed.items || [];
      let addedCount = 0;

      for (const item of items) {
        // Generar un ID único basado en el enlace o título
        const uniqueId = item.guid || item.id || item.link || item.title;
        if (!uniqueId) continue;

        const { sector, severity, isLatam, actor } = classify(item);
        const region = isLatam ? 'Latinoamérica' : feed.region;
        const parsedDate = item.isoDate || item.pubDate;

        const inserted = await articlesStore.insert({
          uniqueId,
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
        }).then(() => true).catch((err) => {
          // UNIQUE constraint = duplicado esperado, no un error real.
          if (!/UNIQUE constraint/i.test(err.message)) throw err;
          return false;
        });
        if (inserted) addedCount++;
      }
      feedStatus[feed.id] = { status: 'ok', added: addedCount };
      if (addedCount > 0) console.log(`  ✓ ${feed.name}: +${addedCount} nuevos`);
    } catch (err) {
      feedStatus[feed.id] = { status: 'error', message: err.message };
      console.log(`  ✗ ${feed.name}: ${err.message}`);
    }
  }));

  return feedStatus;
}

app.get('/api/feeds', async (req, res) => {
  // Fallback de primer arranque: si Turso aún no tiene artículos (el cron
  // nunca corrió), se refresca una vez para no mostrar el dashboard vacío.
  let feedStatus = {};
  const countBefore = await articlesStore.count();
  if (countBefore === 0) {
    console.log('[FEEDS] Sin artículos en Turso — refresco de respaldo en la primera carga.');
    feedStatus = await refreshAllFeeds();
  }

  const allArticles = await articlesStore.listAll();
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

  allArticles.forEach(item => {
    const itemTime = new Date(item.date).getTime();
    const age = now - itemTime;
    const responseItem = { ...item, dateAgo: timeAgo(item.date) };

    if (age <= SIXTY_DAYS_MS) recientes.push(responseItem);
    else historico.push(responseItem);
  });

  // listAll() ya ordena por date DESC, pero se mantiene el sort explícito por
  // si algún artículo llega sin fecha parseable.
  const sorter = (a, b) => new Date(b.date) - new Date(a.date);
  recientes.sort(sorter);
  historico.sort(sorter);

  console.log(`[API] Respondidos: ${recientes.length} Recientes | ${historico.length} Histórico\n`);

  res.json({
    success: true,
    total: allArticles.length,
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
app.delete('/api/feeds', async (req, res) => {
  const { filterType, filterValue } = req.body;
  const before = await articlesStore.count();

  if (filterType === 'all') {
    await articlesStore.deleteAll();
  } else if (filterType === 'older_than_60' || filterType === 'historico_all') {
    const cutoff = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString();
    await articlesStore.deleteOlderThan(cutoff);
  } else if (filterType === 'older_than_365') {
    const cutoff = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString();
    await articlesStore.deleteOlderThan(cutoff);
  } else if (filterType === 'feedId' && filterValue) {
    await articlesStore.deleteByFeedId(filterValue);
  }

  const remaining = await articlesStore.count();
  const deleted = before - remaining;
  console.log(`[DELETE] Limpiados ${deleted} registros. (Filtro: ${filterType})`);

  res.json({ success: true, deleted, remaining });
});

// ─── ENDPOINTS: GESTIÓN DE ASSETS (DOMINIOS) ──────────────────────────────────
app.get('/api/assets', async (req, res) => {
  res.json(await assetsStore.listAll());
});

app.post('/api/assets', async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Dominio requerido' });

  // Evitar duplicados
  if (await assetsStore.existsByDomain(domain)) {
    return res.status(400).json({ error: 'El dominio ya está en monitoreo' });
  }

  const id = Math.random().toString(36).slice(2, 9);
  const scanResult = await scanDomain(domain);
  const newAsset = { id, domain, ...scanResult };

  await assetsStore.insert(newAsset);
  res.json(newAsset);
});

app.get('/api/assets/scan/:id', async (req, res) => {
  const asset = await assetsStore.findById(req.params.id);
  if (!asset) return res.status(404).json({ error: 'Asset no encontrado' });

  // Persistir hallazgos previos
  const scanResult = await scanDomain(asset.domain, asset.subdomains || []);
  await assetsStore.updateScanResult(asset.id, scanResult);
  res.json({ ...asset, ...scanResult });
});

app.post('/api/assets/recon/:id', async (req, res) => {
  const asset = await assetsStore.findById(req.params.id);
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
  const asset = await assetsStore.findById(req.params.id);
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
app.get('/api/assets/fb-scraper/:id', async (req, res) => {
  const asset = await assetsStore.findById(req.params.id);
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

// POST: dispara un escaneo real con Apify de forma asíncrona.
// Antes usaba .call(), que bloquea la petición hasta que el actor termina
// (potencialmente minutos) — inviable en una función serverless con límite de
// duración. Ahora usa .start(): la petición vuelve de inmediato con
// started:true, y es Apify quien llama de vuelta a
// /api/webhooks/apify/brand-monitor (ya protegido con APIFY_WEBHOOK_SECRET
// desde la Fase 0) cuando el run termina. Ese webhook ya sabe procesar
// exactamente el formato de salida de este actor (typosquatDomains,
// socialMediaProfiles, webMentions) y persistir el resultado — es la misma
// ruta por la que ya entran los hallazgos hoy.
app.post('/api/assets/fb-scraper/:id', async (req, res) => {
  const asset = await assetsStore.findById(req.params.id);
  if (!asset) return res.status(404).json({ error: 'Asset no encontrado' });

  const brandKeyword = asset.domain.split('.')[0];
  console.log(`[APIFY] Disparando Brand Protection Monitor (async) para: ${brandKeyword} (Dominio: ${asset.domain})`);

  if (!APIFY_WEBHOOK_URL) {
    return res.status(503).json({
      error: 'APIFY_WEBHOOK_URL no configurada — no se puede recibir el resultado del escaneo asíncrono.',
    });
  }

  try {
    const run = await apifyClient.actor('ryanclinton/brand-protection-monitor').start(
      {
        searchQueries: [brandKeyword],
        maxResults: 20,
        includeSocialMedia: true,
        includeMarketplaces: true,
        includeDomains: true,
        proxyConfiguration: { useApifyProxy: true },
      },
      {
        webhooks: [
          {
            eventTypes: ['ACTOR.RUN.SUCCEEDED'],
            requestUrl: `${APIFY_WEBHOOK_URL}?domain=${encodeURIComponent(asset.domain)}`,
            headersTemplate: JSON.stringify({ 'X-Webhook-Secret': APIFY_WEBHOOK_SECRET }),
          },
        ],
      }
    );

    console.log(`[APIFY] Run iniciado (${run.id}) para ${brandKeyword}. El resultado llegará por webhook.`);
    res.json({ success: true, started: true, runId: run.id, message: 'Escaneo iniciado; los resultados llegarán de forma asíncrona.' });
  } catch (err) {
    console.error('[APIFY] Brand Monitor Error:', err.message);
    res.status(500).json({ error: 'Error iniciando Brand Protection Monitor', details: err.message });
  }
});

app.delete('/api/assets/:id', async (req, res) => {
  console.log(`[ASSETS] Petición para eliminar asset: ${req.params.id}`);
  const deleted = await assetsStore.deleteById(req.params.id);
  console.log(`[ASSETS] Asset ${deleted ? 'eliminado' : 'no encontrado'}: ${req.params.id}`);
  res.json({ success: true, deleted });
});

// Purga de datos con retención por tiempo. Antes solo cubría sensor_telemetry;
// sensor_detections y brand_protection_findings crecían sin límite. Extraída
// a función de módulo para que el cron diario la reutilice sin duplicar lógica.
async function cleanupRetention() {
  const [telemetry, detections, matches, brandFindings, intel, resolvedVulns] = await Promise.all([
    new Promise((resolve, reject) => {
      db.run("DELETE FROM sensor_telemetry WHERE timestamp < datetime('now', '-30 days')", function (err) {
        if (err) return reject(err);
        resolve(this.changes);
      });
    }),
    new Promise((resolve, reject) => {
      db.run("DELETE FROM sensor_detections WHERE timestamp < datetime('now', '-30 days')", function (err) {
        if (err) return reject(err);
        resolve(this.changes);
      });
    }),
    new Promise((resolve, reject) => {
      db.run("DELETE FROM threat_intel_matches WHERE matched_at < datetime('now', '-30 days')", function (err) {
        if (err) return reject(err);
        resolve(this.changes);
      });
    }),
    new Promise((resolve, reject) => {
      db.run("DELETE FROM brand_protection_findings WHERE detected_at < datetime('now', '-180 days')", function (err) {
        if (err) return reject(err);
        resolve(this.changes);
      });
    }),
    intelIngest.purgeExpiredIntel(),
    // Hallazgos resueltos (software actualizado/desinstalado): se retienen
    // más tiempo que telemetría (90 días vs 30) porque siguen teniendo valor
    // de auditoría — "¿cuándo se corrigió este CVE en este equipo?" — pero sin
    // límite crecían indefinidamente, a diferencia de todo lo demás en este
    // módulo. Los 'open' nunca se tocan aquí.
    new Promise((resolve, reject) => {
      db.run("DELETE FROM endpoint_vulnerabilities WHERE status = 'resolved' AND last_confirmed < datetime('now', '-90 days')", function (err) {
        if (err) return reject(err);
        resolve(this.changes);
      });
    }),
  ]);
  console.log(`[DB] Retención aplicada. Eliminados: telemetría=${telemetry}, detecciones=${detections}, matches=${matches}, brand_findings=${brandFindings}, IOCs=${intel.indicators}, observaciones=${intel.observations}, vulns_resueltas=${resolvedVulns}`);
  return { telemetry, detections, matches, brandFindings, intel, resolvedVulns };
}

// En modo local, la limpieza corre cada 24h en el mismo proceso largo. En
// Vercel no hay proceso largo — el cron diario hace el mismo trabajo una vez
// al día (ver vercel.json).
if (!process.env.VERCEL) {
  setInterval(() => cleanupRetention().catch((err) => console.error('[DB] Error en limpieza de retención:', err.message)), 24 * 60 * 60 * 1000);
}

// ─── INTEGRACIÓN ALIENVAULT OTX ───────────────────────────────────────────────
// El caché ya no vive en un objeto de módulo (`let otxCache = {...}`): en
// serverless cada invocación arranca un proceso nuevo, así que esa variable se
// reiniciaba en cada petición y el TTL de 15 min nunca se cumplía de verdad —
// cada request pagaba el costo completo de ir a la API de OTX. Ahora el caché
// vive en Turso (tabla otx_cache) y lo repuebla el cron /api/cron/refresh-otx;
// las rutas de lectura solo consultan Turso, con un refresco síncrono de
// respaldo solo si el caché está realmente vacío (primer arranque, antes de
// que el cron corra por primera vez).
const OTX_API_KEY = process.env.OTX_API_KEY || '';
const OTX_BASE = 'https://otx.alienvault.com/api/v1';

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
  console.log('[OTX] Actualizando datos desde AlienVault OTX...');

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

  await otxCacheStore.write({ pulses: allPulses, indicators: allIndicators });
  console.log(`[OTX] ✓ ${allPulses.length} pulses, ${allIndicators.length} indicadores cargados.`);
  return { pulses: allPulses, indicators: allIndicators };
}

/** Lee el caché de Turso; si está totalmente vacío (nunca corrió el cron), refresca una vez. */
async function getOtxCache() {
  const cache = await otxCacheStore.read();
  if (cache.lastFetch > 0) return cache;
  const fresh = await refreshOTXData();
  return { ...fresh, lastFetch: Date.now() };
}

// --- Endpoints OTX ---
app.get('/api/otx/pulses', async (req, res) => {
  if (!OTX_API_KEY) return res.status(503).json({ error: 'OTX no configurado' });
  const cache = await getOtxCache();
  res.json({ success: true, count: cache.pulses.length, pulses: cache.pulses, cachedAt: cache.lastFetch });
});

app.get('/api/otx/indicators', async (req, res) => {
  if (!OTX_API_KEY) return res.status(503).json({ error: 'OTX no configurado' });
  const cache = await getOtxCache();

  let filtered = cache.indicators;
  const { type, source, limit } = req.query;
  if (type) filtered = filtered.filter(i => i.type === type);
  if (source) filtered = filtered.filter(i => i.source === source);
  const maxResults = Math.min(parseInt(limit) || 500, 1000);

  // Estadísticas por tipo
  const typeStats = {};
  cache.indicators.forEach(i => { typeStats[i.type] = (typeStats[i.type] || 0) + 1; });

  res.json({
    success: true,
    total: cache.indicators.length,
    filtered: filtered.length,
    types: typeStats,
    indicators: filtered.slice(0, maxResults),
    cachedAt: cache.lastFetch
  });
});

app.get('/api/otx/adversaries', async (req, res) => {
  if (!OTX_API_KEY) return res.status(503).json({ error: 'OTX no configurado' });
  const cache = await getOtxCache();

  const counts = {};
  cache.pulses.forEach(p => {
    if (p.adversary) {
      counts[p.adversary] = (counts[p.adversary] || 0) + 1;
    }
  });

  const sorted = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({ name, count }));

  res.json({ success: true, adversaries: sorted, cachedAt: cache.lastFetch });
});

app.get('/api/otx/industries', async (req, res) => {
  if (!OTX_API_KEY) return res.status(503).json({ error: 'OTX no configurado' });
  const cache = await getOtxCache();

  const { source } = req.query;
  const counts = {};

  cache.pulses.forEach(p => {
    if (source && source !== 'TODOS' && p.source !== source) return;

    (p.industries || []).forEach(ind => {
      counts[ind] = (counts[ind] || 0) + 1;
    });
  });

  const sorted = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({ name, count }));

  res.json({ success: true, industries: sorted, cachedAt: cache.lastFetch });
});

app.post('/api/otx/refresh', async (req, res) => {
  if (!OTX_API_KEY) return res.status(503).json({ error: 'OTX no configurado' });
  const fresh = await refreshOTXData();
  res.json({ success: true, pulses: fresh.pulses.length, indicators: fresh.indicators.length });
});

// ─── MOTOR DE INTELIGENCIA MULTI-FUENTE (Fase 3) ─────────────────────────────
// Estado de ingesta por fuente — reemplaza el /api/cron/status para lo que
// respecta específicamente a IOCs (ese otro endpoint cubre feeds/OTX/scans).
app.get('/api/intel/stats', async (req, res) => {
  const [bySource, totalRow] = await Promise.all([
    dbLayer.all(
      `SELECT source, COUNT(*) as count, MIN(first_seen) as oldest, MAX(last_seen) as newest
       FROM threat_indicators WHERE expires_at > CURRENT_TIMESTAMP GROUP BY source`
    ),
    dbLayer.get(`SELECT COUNT(*) as total FROM threat_indicators WHERE expires_at > CURRENT_TIMESTAMP`),
  ]);
  const state = await dbLayer.all('SELECT * FROM intel_source_state ORDER BY source');
  res.json({ success: true, bySource, total: totalRow.total, sourceState: state });
});

// Paginado desde DB — sustituye el .slice() sobre el blob de /api/otx/indicators,
// y cubre TODAS las fuentes, no solo OTX.
app.get('/api/intel/indicators', async (req, res) => {
  const type = req.query.type;
  const source = req.query.source;
  const q = req.query.q;
  const limit = Math.min(Number(req.query.limit) || 100, 500);
  const offset = Math.max(Number(req.query.offset) || 0, 0);

  const where = ['expires_at > CURRENT_TIMESTAMP'];
  const args = [];
  if (type) { where.push('ioc_type = ?'); args.push(type); }
  if (source) { where.push('source = ?'); args.push(source); }
  if (q) { where.push('ioc_value LIKE ?'); args.push(`%${q}%`); }
  const whereSql = where.join(' AND ');

  const [rows, countRow] = await Promise.all([
    dbLayer.all(
      `SELECT ioc_type, ioc_value, source, confidence, threat_class, malware_family, reference, last_seen
       FROM threat_indicators WHERE ${whereSql} ORDER BY last_seen DESC LIMIT ? OFFSET ?`,
      [...args, limit, offset]
    ),
    dbLayer.get(`SELECT COUNT(*) as total FROM threat_indicators WHERE ${whereSql}`, args),
  ]);
  res.json({ success: true, indicators: rows, total: countRow.total, limit, offset });
});

// Consulta manual del analista: pega una lista de IPs/dominios/hashes y ve si
// ya están en el catálogo, sin tener que esperar a que un sensor los reporte.
app.post('/api/intel/lookup', async (req, res) => {
  const { values } = req.body || {};
  if (!Array.isArray(values) || values.length === 0) {
    return res.status(400).json({ error: 'Se requiere un array "values" con al menos un indicador.' });
  }
  const normalized = values
    .slice(0, 100)
    .map(v => intelLookup.normalizeIoc(String(v)))
    .filter(Boolean);
  const results = await intelLookup.lookupIndicators(normalized.map(n => n.ioc_value));
  res.json({
    success: true,
    matches: Object.fromEntries(results),
    unmatched: normalized.map(n => n.ioc_value).filter(v => !results.has(v)),
  });
});

// Ledger de coincidencias (en vivo + retro) para un agente o global.
app.get('/api/intel/matches', async (req, res) => {
  const { agent_id } = req.query;
  const rows = agent_id
    ? await dbLayer.all('SELECT * FROM threat_intel_matches WHERE agent_id = ? ORDER BY matched_at DESC LIMIT 200', [agent_id])
    : await dbLayer.all('SELECT * FROM threat_intel_matches ORDER BY matched_at DESC LIMIT 200');
  res.json({ success: true, matches: rows });
});

// ─── VULNERABILIDADES SOBRE INVENTARIO (Fase 4) ──────────────────────────────
app.get('/api/vulns/summary', async (req, res) => {
  const [totals, kevRow, endpointsAffected, topCves, coverage, catalogStats] = await Promise.all([
    dbLayer.all(`SELECT c.cvss_severity as severity, COUNT(*) as count
                 FROM endpoint_vulnerabilities e JOIN cve_catalog c ON c.cve_id = e.cve_id
                 WHERE e.status = 'open' GROUP BY c.cvss_severity`),
    dbLayer.get(`SELECT COUNT(*) as c FROM endpoint_vulnerabilities e JOIN cve_catalog c ON c.cve_id = e.cve_id
                 WHERE e.status = 'open' AND c.in_kev = 1`),
    dbLayer.get(`SELECT COUNT(DISTINCT agent_id) as c FROM endpoint_vulnerabilities WHERE status = 'open'`),
    dbLayer.all(`SELECT e.cve_id, c.epss_score, c.in_kev, COUNT(DISTINCT e.agent_id) as endpoints
                 FROM endpoint_vulnerabilities e JOIN cve_catalog c ON c.cve_id = e.cve_id
                 WHERE e.status = 'open' GROUP BY e.cve_id ORDER BY c.in_kev DESC, c.epss_score DESC LIMIT 10`),
    dbLayer.get(`SELECT
                   (SELECT COUNT(DISTINCT name_normalized) FROM unmapped_software) as unmapped,
                   (SELECT COUNT(DISTINCT product_name) FROM endpoint_vulnerabilities) as mapped`),
    dbLayer.get(`SELECT COUNT(*) as cves FROM cve_catalog`),
  ]);

  const totalsByLevel = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const row of totals) {
    const key = (row.severity || '').toLowerCase();
    if (totalsByLevel[key] !== undefined) totalsByLevel[key] = row.count;
  }
  const rangesRow = await dbLayer.get('SELECT COUNT(*) as c FROM cve_affected_ranges');
  const lastSync = await dbLayer.get(`SELECT last_run FROM intel_source_state WHERE source = 'nvd_kev'`);

  res.json({
    success: true,
    totals: totalsByLevel,
    kev_count: kevRow.c,
    endpoints_affected: endpointsAffected.c,
    top_cves: topCves,
    coverage: { mapped_products: coverage.mapped, unmapped_products: coverage.unmapped },
    catalog: { cves: catalogStats.cves, ranges: rangesRow.c, last_sync: lastSync?.last_run || null },
  });
});

app.get('/api/vulns/endpoint/:agent_id', async (req, res) => {
  const { agent_id } = req.params;
  const [endpointRow, findings] = await Promise.all([
    dbLayer.get('SELECT vuln_state, last_correlated, software_info FROM sensor_endpoints WHERE agent_id = ?', [agent_id]),
    dbLayer.all(
      `SELECT e.*, c.cvss_score, c.cvss_severity, c.description, c.in_kev, c.kev_due_date, c.kev_ransomware, c.epss_score, c.epss_percentile
       FROM endpoint_vulnerabilities e JOIN cve_catalog c ON c.cve_id = e.cve_id
       WHERE e.agent_id = ? AND e.status = 'open'
       ORDER BY c.in_kev DESC, c.epss_score DESC, c.cvss_score DESC`,
      [agent_id]
    ),
  ]);

  // unmapped_software es una tabla GLOBAL (no lleva agent_id: agrupa por
  // producto para no repetir el mismo hallazgo "no evaluado" por cada
  // endpoint que lo tiene instalado). Para mostrar el subconjunto de ESTE
  // endpoint, se cruza en JS contra su inventario actual — evitar esto
  // implicaría o bien duplicar unmapped_software por agente (mucho más
  // volumen) o un JOIN por LIKE sobre texto libre (frágil y lento).
  let unmapped = [];
  if (endpointRow?.software_info) {
    try {
      const software = JSON.parse(endpointRow.software_info) || [];
      const normalizedNames = software.map(s => vulnDictionary.normalizeProductName(s.name)).filter(Boolean);
      if (normalizedNames.length) {
        const placeholders = normalizedNames.map(() => '?').join(',');
        unmapped = await dbLayer.all(
          `SELECT sample_name as name, sample_version as version, sample_publisher as publisher, reason
           FROM unmapped_software WHERE name_normalized IN (${placeholders})`,
          normalizedNames
        );
      }
    } catch { /* software_info corrupto o vacío: unmapped queda [] */ }
  }

  res.json({ success: true, findings, unmapped, vuln_state: endpointRow?.vuln_state || 'pending', last_correlated: endpointRow?.last_correlated || null });
});

app.get('/api/vulns/cve/:cve_id', async (req, res) => {
  const { cve_id } = req.params;
  const [cve, affectedEndpoints] = await Promise.all([
    dbLayer.get('SELECT * FROM cve_catalog WHERE cve_id = ?', [cve_id]),
    dbLayer.all(
      `SELECT e.agent_id, s.hostname, e.product_name, e.product_version, e.matched_rule
       FROM endpoint_vulnerabilities e JOIN sensor_endpoints s ON s.agent_id = e.agent_id
       WHERE e.cve_id = ? AND e.status = 'open'`,
      [cve_id]
    ),
  ]);
  if (!cve) return res.status(404).json({ error: 'CVE no encontrado en el catálogo local.' });
  res.json({ success: true, cve, affected_endpoints: affectedEndpoints });
});

app.post('/api/vulns/recompute/:agent_id', async (req, res) => {
  const { agent_id } = req.params;
  const started = Date.now();
  try {
    const result = await vulnCorrelate.correlateEndpoint(agent_id);
    res.json({ success: true, ...result, duration_ms: Date.now() - started });
  } catch (err) {
    console.error('[VULN] Error recalculando endpoint:', err.message);
    res.status(500).json({ error: 'Error recalculando vulnerabilidades: ' + err.message });
  }
});

app.get('/api/vulns/dictionary', async (req, res) => {
  const dict = await dbLayer.all(`
    SELECT d.*, (SELECT COUNT(*) FROM endpoint_vulnerabilities e WHERE e.cpe_vendor = d.cpe_vendor AND e.cpe_product = d.cpe_product) as endpoints_using
    FROM cpe_dictionary d ORDER BY d.cpe_vendor, d.cpe_product`);
  res.json({ success: true, dictionary: dict });
});

app.post('/api/vulns/dictionary', async (req, res) => {
  const { match_kind, match_value, publisher_hint, cpe_vendor, cpe_product } = req.body || {};
  if (!match_kind || !match_value || !cpe_vendor || !cpe_product) {
    return res.status(400).json({ error: 'match_kind, match_value, cpe_vendor y cpe_product son obligatorios.' });
  }
  await dbLayer.run(
    `INSERT INTO cpe_dictionary (match_kind, match_value, publisher_hint, cpe_vendor, cpe_product)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(match_kind, match_value, publisher_hint) DO UPDATE SET cpe_vendor = excluded.cpe_vendor, cpe_product = excluded.cpe_product`,
    [match_kind, match_value.toLowerCase(), publisher_hint || null, cpe_vendor, cpe_product]
  );
  vulnDictionary.invalidateDictionaryCache();
  res.json({ success: true });
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

app.post('/api/sensors/sysinfo', requireAgentToken, async (req, res) => {
  const { agent_id, hardware, software, hotfixes } = req.body;
  const hwJson = JSON.stringify(hardware || {});
  const swJson = JSON.stringify(software || []);
  const hotfixesJson = JSON.stringify(hotfixes || []);
  const osBuild = hardware?.os_version || null;

  // sw_hash detecta si el inventario cambió desde la última correlación de
  // vulnerabilidades (Fase 4) SIN correlacionar aquí mismo — eso implicaría
  // un JOIN contra cve_affected_ranges en la ruta caliente del agente, en
  // cada reinicio. Solo se marca 'pending' para que el cron lo recoja.
  const newHash = vulnCorrelate.hashSoftware(software || []);
  const prevRow = await dbLayer.get('SELECT sw_hash FROM sensor_endpoints WHERE agent_id = ?', [agent_id]);
  const vulnStateUpdate = !prevRow || prevRow.sw_hash !== newHash ? `, vuln_state='pending'` : '';

  db.run(`UPDATE sensor_endpoints SET hardware_info=?, software_info=?, sw_hash=?, os_build=?, hotfixes=?, status='ONLINE', last_seen=CURRENT_TIMESTAMP${vulnStateUpdate} WHERE agent_id=?`, [hwJson, swJson, newHash, osBuild, hotfixesJson, agent_id], function(err) {
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

// Empaqueta el sensor listo para desplegar: sensor.py + agent.config.json ya
// relleno con el dominio real (derivado de la propia petición, no de una env
// var aparte — funciona igual en Vercel y en local) y el AGENT_TOKEN vigente.
// Evita que cada analista tenga que copiar/editar el config a mano en cada
// endpoint. Protegido por requireAuth (lista blanca de server/app.js más
// arriba) porque el ZIP contiene el token del canal EDR.
//
// sensor.py y rules.py se leen desde public/, NO desde agent/: .vercelignore
// excluye agent/ completo del despliegue serverless (correcto — ahí vive
// también build_exe.ps1, el .spec de PyInstaller, certificados de prueba,
// etc. que no deben viajar al bundle), así que un fs.existsSync() contra
// agent/sensor.py devolvía siempre false en producción y este endpoint daba
// 500. public/ SÍ se despliega (es el mismo directorio que sirve
// sensor-setup.exe), y no contiene ningún secreto — el token se inyecta
// recién aquí, por request. rules.py es obligatorio desde la Fase 2 (motor de
// detección MITRE): sensor.py hace `import rules`, así que sin este archivo
// junto al script el modo consola falla al arrancar. Mantener ambos
// sincronizados con agent/ tras cualquier cambio (ver nota homóloga al inicio
// de agent/sensor.py).
app.get('/api/sensors/download-package', (req, res) => {
  if (!AGENT_TOKEN) {
    return res.status(503).json({ error: 'AGENT_TOKEN no está configurado en el servidor — no se puede generar un paquete funcional.' });
  }

  const sensorPath = path.join(__dirname, '..', 'public', 'sensor.py');
  const rulesPath = path.join(__dirname, '..', 'public', 'rules.py');

  if (!fs.existsSync(sensorPath) || !fs.existsSync(rulesPath)) {
    return res.status(500).json({ error: 'sensor.py o rules.py no encontrados en el servidor.' });
  }

  const serverUrl = `${req.protocol}://${req.get('host')}`;
  const config = {
    _comentario: 'Generado automáticamente desde el dashboard — listo para usar, no requiere edición.',
    server_url: serverUrl,
    agent_token: AGENT_TOKEN,
    ca_cert: null,
    verify_tls: true,
    poll_interval_seconds: 30,
  };

  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', 'attachment; filename="cyberintel-sensor.zip"');

  const archive = archiver('zip', { zlib: { level: 9 } });
  archive.on('error', (err) => {
    console.error('[DOWNLOAD] Error generando el paquete del sensor:', err.message);
    if (!res.headersSent) res.status(500).json({ error: 'Error generando el paquete' });
  });
  archive.pipe(res);

  archive.file(sensorPath, { name: 'sensor.py' });
  archive.file(rulesPath, { name: 'rules.py' });
  archive.append(JSON.stringify(config, null, 2), { name: 'agent.config.json' });
  archive.append(
    'CyberIntel EC — Sensor EDR (modo consola)\n' +
    '===========================================\n\n' +
    'Para la mayoría de los casos usa el instalador de Windows (sensor-setup.exe,\n' +
    'botón "Descargar instalador" en el dashboard): instala el sensor como\n' +
    'Servicio de Windows persistente, con arranque automático e incluye su propio\n' +
    'desinstalador. Este ZIP es la alternativa en modo consola/código fuente.\n\n' +
    'Este paquete ya viene configurado con el servidor y el token de este despliegue.\n\n' +
    'Instalación:\n' +
    '  1. Requiere Python 3.8+ instalado en el endpoint (Windows).\n' +
    '  2. Descomprimir este ZIP en cualquier carpeta del equipo.\n' +
    '  3. Ejecutar: python sensor.py\n\n' +
    'El agente se identifica solo por el número de serie del BIOS y no requiere\n' +
    'ninguna dependencia adicional (pip install) en este modo.\n\n' +
    'Para desinstalar: cierra la ventana/proceso de sensor.py (Ctrl+C) y borra\n' +
    'esta carpeta — en modo consola no queda registrado como servicio ni en el\n' +
    'sistema.\n',
    { name: 'LEEME.txt' }
  );

  archive.finalize();
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
app.post('/api/sensors/telemetry', requireAgentToken, async (req, res) => {
  const { agent_id, events } = req.body;

  if (!events || !Array.isArray(events)) return res.status(400).json({ error: 'Formato inválido' });

  const stmt = db.prepare(`INSERT INTO sensor_telemetry
    (agent_id, event_type, process_name, parent_process, target_path, dst_ip, dst_domain, risk_score, mitre_id, mitre_tactic, mitre_technique, severity, raw_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);

  // Buffer en memoria para telemetría volátil (INFO)
  global.volatileTelemetry = global.volatileTelemetry || {};

  // Normaliza los candidatos del lote (dst_ip, file_hash) y hace UNA consulta
  // indexada contra threat_indicators (Fase 3) en vez del .find() lineal sobre
  // el blob completo de otx_cache.indicators que se deserializaba en cada
  // request. También reemplaza el alcance "solo IPv4 de OTX" por cualquier
  // fuente (ThreatFox, URLhaus, MalwareBazaar, Feodo, Tor) y cualquier tipo
  // (ipv4, dominio, hash) que el evento traiga.
  const candidateEntries = events
    .map(ev => {
      const fromIp = ev.dst_ip ? intelLookup.normalizeIoc(ev.dst_ip, 'ipv4') : null;
      const fromHash = !fromIp && ev.file_hash ? intelLookup.normalizeIoc(ev.file_hash) : null;
      return { ev, ioc: fromIp || fromHash };
    });
  const candidateValues = candidateEntries.map(c => c.ioc?.ioc_value).filter(Boolean);
  const matchesByValue = await intelLookup.lookupIndicators(candidateValues);

  // Conjunto acotado de observaciones de red nuevas para este lote — alimenta
  // la retro-correlación diaria sin persistir el log completo de tráfico.
  const observations = [];

  // Riesgo del lote. Se acumula dentro del loop para que incluya el enriquecimiento
  // de threat intel, que es lo que se perdía al recalcularlo aparte.
  let totalRisk = 0;
  const matchWrites = []; // promesas de upsertMatch + sensor_detections, resueltas antes de responder

  candidateEntries.forEach(({ ev, ioc }) => {
    let extraRisk = 0;
    let scored = null;

    if (ioc) {
      const rows = matchesByValue.get(ioc.ioc_value);
      scored = intelLookup.scoreFromMatches(rows);
      if (ev.dst_ip) {
        observations.push({ ioc_type: ioc.ioc_type, ioc_value: ioc.ioc_value, sample_process: ev.process_name || null });
      }
      if (scored) {
        extraRisk = scored.risk;
        // upsertMatch es idempotente por (agent_id, indicator): si ya existe,
        // no duplica la detección ni vuelve a sumar riesgo — evita que un
        // beacon repetido a la misma IP/hash maliciosa dispare
        // THREAT_INTEL_MATCH (y sume score) en cada lote.
        matchWrites.push(
          intelLookup.upsertMatch(agent_id, ioc.ioc_value, ioc.ioc_type, scored, 'live').then(({ isNew }) => {
            if (!isNew) return;
            return dbLayer.run(
              `INSERT INTO sensor_detections (agent_id, detection_type, severity, score, details, behavior_chain)
               VALUES (?, ?, ?, ?, ?, ?)`,
              [agent_id, scored.detectionType, scored.severity, scored.risk,
               `${scored.bestSource}${scored.sourceCount > 1 ? ` +${scored.sourceCount - 1} fuentes` : ''}: ${scored.malwareFamily || scored.threatClass} — indicador ${ioc.ioc_value}`,
               JSON.stringify(ev)]
            );
          }).catch(err => console.error('[EDR] Error registrando match de intel:', err.message))
        );
      }
    }

    const finalRisk = (ev.risk_score || 0) + extraRisk;
    totalRisk += finalRisk;
    // event_type se añade explícitamente: `ev.type` es el nombre que emite el
    // agente, pero el frontend lee `event_type` desde raw_json. Sin esto el
    // timeline mostraba "INFO" en todos los eventos persistidos.
    const enrichedEvent = {
      ...ev, event_type: ev.type,
      intel_match: scored ? `${scored.bestSource}: ${scored.malwareFamily || scored.threatClass}` : null,
      timestamp: ev.timestamp || new Date().toISOString(),
    };

    if (finalRisk >= 30) {
      // PERSISTENTE: Guardar en DB porque hay riesgo relevante (Medio, Alto o Crítico)
      // parent_process ahora viene poblado de verdad: el agente (Fase 2) envía
      // parent_name junto al evento de proceso — antes esta columna quedaba
      // siempre null porque nada la llenaba en ninguna ruta.
      stmt.run([
        agent_id, ev.type, ev.process_name || null, ev.parent_name || null, ev.target_path || null,
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

  if (observations.length) {
    // await, no fire-and-forget: la retro-correlación diaria depende de que
    // estas filas ya estén escritas. No es una ruta sensible a latencia (el
    // agente no espera respuesta interactiva), así que no hay razón para
    // arriesgar una condición de carrera a cambio de unos ms.
    await intelLookup.recordObservations(agent_id, observations).catch(err =>
      console.error('[EDR] Error registrando observaciones de red:', err.message));
  }
  await Promise.all(matchWrites);

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

// Estado de los 2 cron jobs diarios. Sin acceso directo a logs de Vercel, esta
// es la única forma de confirmar desde el dashboard que corrieron de verdad y
// cuándo fue su última ejecución exitosa o fallida.
// OJO: no puede vivir bajo /api/cron/* — vercel.json reescribe ese prefijo
// completo al filesystem de api/cron/*.js, así que esta ruta de Express nunca
// se alcanzaría en producción (solo funcionaba corriendo server.js en local).
app.get('/api/cron-status', async (req, res) => {
  const runs = await cronRuns.listAll();
  res.json({ success: true, jobs: runs });
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

// Matriz ATT&CK agregada: cuántas veces se observó cada técnica, en cuántos
// endpoints distintos, y cuándo fue la última vez — la primera vista que
// explota los campos mitre_id/mitre_tactic/mitre_technique que ya se
// almacenaban desde el principio pero ningún endpoint devolvía agregados
// (solo viajaban sueltos dentro de raw_json en /behavior/:agent_id).
app.get('/api/sensors/attack-matrix', (req, res) => {
  db.all(
    `SELECT mitre_id, mitre_tactic, mitre_technique,
            COUNT(*) as event_count,
            COUNT(DISTINCT agent_id) as endpoint_count,
            MAX(timestamp) as last_seen
     FROM sensor_telemetry
     WHERE mitre_id IS NOT NULL
     GROUP BY mitre_id, mitre_tactic, mitre_technique
     ORDER BY last_seen DESC`,
    (err, rows) => {
      if (err) {
        console.error('[EDR] Error agregando matriz ATT&CK:', err.message);
        return res.status(500).json({ error: 'Error interno' });
      }
      res.json({ success: true, techniques: rows || [] });
    }
  );
});

// Eventos que dispararon una técnica MITRE concreta — el drill-down desde la
// matriz. Filtra sobre raw_json porque additional_techniques (técnicas
// secundarias de un mismo evento, ver agent/rules.py) no tiene columna propia
// y un evento puede aparecer bajo varias técnicas a la vez.
app.get('/api/sensors/attack-matrix/:mitre_id', (req, res) => {
  const { mitre_id } = req.params;
  db.all(
    `SELECT t.*, s.hostname
     FROM sensor_telemetry t
     JOIN sensor_endpoints s ON t.agent_id = s.agent_id
     WHERE t.mitre_id = ?
     ORDER BY t.timestamp DESC LIMIT 50`,
    [mitre_id],
    (err, rows) => {
      if (err) {
        console.error('[EDR] Error leyendo eventos de técnica:', err.message);
        return res.status(500).json({ error: 'Error interno' });
      }
      res.json({ success: true, events: rows || [] });
    }
  );
});

// ─── WEBHOOKS EXTERNOS (APIFY / OTROS) ───────────────────────────────────────
// (Constantes declaradas más arriba, junto a APIFY_WEBHOOK_URL, para que
// /api/assets/fb-scraper/:id — que dispara el run cuyo resultado llega aquí —
// las tenga disponibles en el mismo lugar donde se leen.)

/**
 * Endpoint para recibir resultados de Apify Brand Protection Monitor vía Webhook.
 * Configuración en Apify:
 * URL: https://TU_URL_PUBLICA/api/webhooks/apify/brand-monitor?domain=tu-dominio.com
 * Method: POST
 * Header: X-Webhook-Secret: <APIFY_WEBHOOK_SECRET>
 * Content-Type: application/json
 */
app.post('/api/webhooks/apify/brand-monitor', async (req, res) => {
  // Falla cerrado igual que el resto de secretos del proyecto: sin valor
  // configurado, se rechaza todo en vez de aceptar cualquier POST anónimo.
  const receivedSecret = req.get('X-Webhook-Secret') || '';
  const a = Buffer.from(receivedSecret);
  const b = Buffer.from(APIFY_WEBHOOK_SECRET);
  const validSecret = APIFY_WEBHOOK_SECRET.length > 0 && a.length === b.length && crypto.timingSafeEqual(a, b);
  if (!validSecret) {
    console.warn(`[WEBHOOK] ⛔ Petición rechazada por secreto inválido/ausente desde ${req.ip}`);
    return res.status(403).json({ error: 'Secreto de webhook inválido o ausente' });
  }

  const { domain } = req.query;
  const payload = req.body;

  if (!domain) return res.status(400).json({ error: 'Falta el parámetro domain en la URL' });

  const asset = await assetsStore.findByDomain(domain);
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

    const fbScraperCache = {
      results: processedResults,
      cachedAt: new Date().toISOString(),
      domain: asset.domain,
      source: 'APIFY_WEBHOOK',
      newFindings: newFindingsCount
    };
    await assetsStore.updateFbScraperCache(asset.id, fbScraperCache);

    console.log(`[WEBHOOK] ✓ Proceso completado para ${domain}. Hallazgos totales: ${processedResults.length}, Nuevos: ${newFindingsCount}`);
    
    res.json({ success: true, newFindings: newFindingsCount, totalProcessed: processedResults.length });

  } catch (err) {
    console.error('[WEBHOOK] Error crítico:', err.message);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Trabajo de fondo reutilizado por los endpoints /api/cron/* (ver api/cron/*.js).
// Se cuelga como propiedades de `app` en vez de exportarlas aparte: app sigue
// siendo la misma función Express que server.js y api/index.js esperan
// recibir de este módulo, y los cron handlers importan server/app y toman
// solo lo que necesitan (app.jobs.refreshAllFeeds, etc.).
app.jobs = {
  refreshAllFeeds, refreshOTXData, autoScanNextAsset, autoScanAssets, autoScanAssetsBudgeted, cleanupRetention,
  ingestAllSources: intelIngest.ingestAllSources,
  runRetroCorrelation: intelLookup.runRetroCorrelation,
  // Promisificado: el cron necesita await sobre esto tras el pase retro, y la
  // firma original es callback-style (mismo patrón que el resto de rutas EDR).
  refreshBehaviorScore: (agentId, addRisk) => new Promise((resolve, reject) => {
    refreshBehaviorScore(agentId, addRisk, (err) => (err ? reject(err) : resolve()));
  }),
  syncVulnCatalog: vulnCatalog.syncVulnCatalog,
  correlateAllPending: vulnCorrelate.correlateAllPending,
};

module.exports = app;

