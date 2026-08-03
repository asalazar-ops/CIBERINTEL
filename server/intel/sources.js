// Fetchers de fuentes de inteligencia abierta — cada uno devuelve un array
// de IOCs YA normalizados a la forma de threat_indicators (sin ioc_type/value
// crudos de cada API, que difieren mucho entre sí: URLhaus da CSV, ThreatFox
// da JSON con IP:puerto pegados, KEV da CVEs no IOCs...). ingest.js solo tiene
// que hacer upsert de lo que estas funciones devuelven, sin conocer el
// formato de ninguna API externa.
//
// Todas las URLs y límites fueron verificados en vivo (ver plan aprobado,
// 2026-08-01): Feodo Tracker está prácticamente muerto (5 IPs, todas
// 'offline', sin actualizar desde marzo) — se conserva por si vuelve a
// activarse pero no debe presentarse como fuente confiable en la UI.

const TOR_EXIT_LIST_URL = 'https://check.torproject.org/torbulkexitlist';
const URLHAUS_RECENT_CSV = 'https://urlhaus.abuse.ch/downloads/csv_recent/';
const FEODO_BLOCKLIST_URL = 'https://feodotracker.abuse.ch/downloads/ipblocklist.json';
const THREATFOX_API = 'https://threatfox-api.abuse.ch/api/v1/';
const MALWAREBAZAAR_API = 'https://mb-api.abuse.ch/api/v1/';

const FETCH_TIMEOUT_MS = 15000;

async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function isPrivateOrReserved(ip) {
  // Ruido interno (RFC1918/loopback/link-local/CGNAT) no debe entrar al
  // catálogo de IOCs: contaminaría endpoint_network_observations con
  // millones de coincidencias triviales (todo tráfico LAN normal).
  if (!ip || typeof ip !== 'string') return true;
  const octets = ip.split('.').map(Number);
  if (octets.length !== 4 || octets.some((o) => Number.isNaN(o))) return true;
  const [a, b] = octets;
  return (
    a === 10 ||
    a === 127 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127) || // CGNAT
    ip === '0.0.0.0'
  );
}

/** Tor exit nodes — lista de texto plano, una IP por línea. Sin auth. */
async function fetchTorExitNodes() {
  const resp = await fetchWithTimeout(TOR_EXIT_LIST_URL);
  if (!resp.ok) throw new Error(`Tor exit list: HTTP ${resp.status}`);
  const text = await resp.text();
  const now = new Date().toISOString();
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#') && !isPrivateOrReserved(l))
    .map((ip) => ({
      ioc_type: 'ipv4', ioc_value: ip, source: 'torexit',
      confidence: 20, threat_class: 'anonymizer', malware_family: null,
      reference: 'Tor Project bulk exit list', ttl_days: 2,
      first_seen: now, last_seen: now,
    }));
}

/** Feodo Tracker — JSON con lista de IPs de botnets bancarios. Sin auth. */
async function fetchFeodo() {
  const resp = await fetchWithTimeout(FEODO_BLOCKLIST_URL);
  if (!resp.ok) throw new Error(`Feodo Tracker: HTTP ${resp.status}`);
  const rows = await resp.json();
  const now = new Date().toISOString();
  return (Array.isArray(rows) ? rows : [])
    .filter((r) => r.ip_address && !isPrivateOrReserved(r.ip_address))
    .map((r) => ({
      ioc_type: 'ipv4', ioc_value: r.ip_address, source: 'feodo',
      confidence: 90, threat_class: 'botnet_cc', malware_family: r.malware || null,
      reference: `Feodo Tracker — puerto ${r.port || '?'}`, ttl_days: 30,
      first_seen: now, last_seen: now,
    }));
}

/**
 * URLhaus recent — CSV incremental por cursor de `id` (columna monotónica
 * creciente). La mayoría de las filas son loaders IoT ELF (Mirai/Mozi) sin
 * relevancia para una flota Windows — se filtran por tags conocidos y se
 * ingieren con confianza baja (30) para que no disparen detección por sí
 * solas, solo corroboren otra fuente.
 */
async function fetchUrlhausRecent({ sinceId = 0, capRows = 3000 } = {}) {
  const resp = await fetchWithTimeout(URLHAUS_RECENT_CSV);
  if (!resp.ok) throw new Error(`URLhaus: HTTP ${resp.status}`);
  const text = await resp.text();
  const now = new Date().toISOString();
  // Verificado en el plan: la abrumadora mayoría de URLhaus recent son
  // loaders IoT ELF (Mirai/Mozi) — irrelevantes para una flota Windows y
  // capaces de inflar la tabla a miles de filas por ~cero verdaderos
  // positivos. Se excluyen del todo (no solo se les baja confianza): bajar
  // confianza las mantenía ocupando espacio e índice sin aportar señal real.
  const iotTagsRx = /\b(elf|mips|arm|mozi|mirai)\b/i;

  const out = [];
  let maxId = sinceId;
  let skippedIot = 0;
  for (const line of text.split('\n')) {
    if (!line || line.startsWith('#')) continue;
    // Formato: "id","dateadded","url","url_status","last_online","threat","tags","urlhaus_link","reporter"
    const cols = line.match(/(?:^|,)("(?:[^"]|"")*"|[^,]*)/g)?.map((c) => c.replace(/^,/, '').replace(/^"|"$/g, '').replace(/""/g, '"'));
    if (!cols || cols.length < 7) continue;
    const id = Number(cols[0]);
    if (!Number.isFinite(id) || id <= sinceId) continue;
    // El cursor avanza sobre TODAS las filas del CSV, incluidas las
    // descartadas por IoT — si solo avanzara sobre las aceptadas, la próxima
    // corrida las volvería a bajar y re-descartar en un bucle inútil.
    if (id > maxId) maxId = id;

    const url = cols[2];
    const tags = cols[6] || '';
    if (!url) continue;
    if (iotTagsRx.test(tags)) { skippedIot++; continue; }
    if (out.length >= capRows) continue;

    let host = null;
    try { host = new URL(url).hostname; } catch { /* URL inválida, se ignora el host */ }

    out.push({
      ioc_type: 'url', ioc_value: url, source: 'urlhaus',
      confidence: 30, threat_class: 'payload_delivery', malware_family: tags || null,
      reference: cols[7] || 'URLhaus', ttl_days: 14,
      first_seen: now, last_seen: now,
    });
    if (host && !isPrivateOrReserved(host)) {
      out.push({
        ioc_type: /^\d+\.\d+\.\d+\.\d+$/.test(host) ? 'ipv4' : 'domain', ioc_value: host, source: 'urlhaus',
        confidence: 30, threat_class: 'payload_delivery', malware_family: tags || null,
        reference: cols[7] || 'URLhaus', ttl_days: 14,
        first_seen: now, last_seen: now,
      });
    }
  }
  return { rows: out, maxId, skippedIot };
}

/** ThreatFox — requiere Auth-Key gratuita (auth.abuse.ch). Sin ella se omite. */
async function fetchThreatFox({ authKey, days = 1 } = {}) {
  if (!authKey) return [];
  const resp = await fetchWithTimeout(THREATFOX_API, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Auth-Key': authKey },
    body: JSON.stringify({ query: 'get_iocs', days }),
  });
  if (!resp.ok) throw new Error(`ThreatFox: HTTP ${resp.status}`);
  const json = await resp.json();
  if (json.query_status !== 'ok' || !Array.isArray(json.data)) return [];
  const now = new Date().toISOString();

  const typeMap = { ip: 'ipv4', 'ip:port': 'ipv4', domain: 'domain', url: 'url', md5_hash: 'md5', sha1_hash: 'sha1', sha256_hash: 'sha256' };
  const classMap = { botnet_cc: 'c2', payload_delivery: 'payload_delivery' };

  return json.data
    .map((ioc) => {
      let value = ioc.ioc || '';
      const rawType = (ioc.ioc_type || '').toLowerCase();
      // ThreatFox pega "ip:port" en un solo campo para IOCs de tipo ip:port —
      // el puerto no aporta a la correlación contra dst_ip del sensor.
      if (rawType === 'ip:port') value = value.split(':')[0];
      const ioc_type = typeMap[rawType] || null;
      if (!ioc_type || !value || (ioc_type === 'ipv4' && isPrivateOrReserved(value))) return null;
      return {
        ioc_type, ioc_value: value, source: 'threatfox',
        confidence: Math.max(50, Number(ioc.confidence_level) || 80),
        threat_class: classMap[ioc.threat_type] || 'c2',
        malware_family: ioc.malware_printable || ioc.malware || null,
        reference: ioc.reference || 'ThreatFox', ttl_days: 90,
        first_seen: now, last_seen: now,
      };
    })
    .filter(Boolean);
}

/** MalwareBazaar — requiere la misma Auth-Key de abuse.ch. Sin ella se omite. */
async function fetchMalwareBazaarRecent({ authKey } = {}) {
  if (!authKey) return [];
  const body = new URLSearchParams({ query: 'get_recent', selector: 'time' });
  const resp = await fetchWithTimeout(MALWAREBAZAAR_API, {
    method: 'POST',
    headers: { 'Auth-Key': authKey, 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!resp.ok) throw new Error(`MalwareBazaar: HTTP ${resp.status}`);
  const json = await resp.json();
  if (json.query_status !== 'ok' || !Array.isArray(json.data)) return [];
  const now = new Date().toISOString();

  return json.data
    .filter((s) => s.sha256_hash)
    .map((s) => ({
      ioc_type: 'sha256', ioc_value: s.sha256_hash.toLowerCase(), source: 'malwarebazaar',
      confidence: 85, threat_class: 'malware_sample',
      malware_family: s.signature || (Array.isArray(s.tags) ? s.tags.join(',') : null),
      reference: 'MalwareBazaar', ttl_days: 180,
      first_seen: now, last_seen: now,
    }));
}

/** Reutiliza los indicadores ya extraídos de OTX (server/app.js: refreshOTXData) para llevarlos a la tabla común. */
function normalizeOtxIndicators(indicators) {
  const typeMap = { IPv4: 'ipv4', IPv6: 'ipv4', domain: 'domain', hostname: 'domain', URL: 'url', 'FileHash-MD5': 'md5', 'FileHash-SHA1': 'sha1', 'FileHash-SHA256': 'sha256' };
  const now = new Date().toISOString();
  return indicators
    .map((ind) => {
      const ioc_type = typeMap[ind.type] || null;
      if (!ioc_type || !ind.indicator) return null;
      if (ioc_type === 'ipv4' && isPrivateOrReserved(ind.indicator)) return null;
      return {
        ioc_type, ioc_value: ind.indicator, source: 'otx',
        confidence: 60, threat_class: 'generic', malware_family: null,
        reference: ind.pulse_name || 'AlienVault OTX', ttl_days: 60,
        first_seen: now, last_seen: now,
      };
    })
    .filter(Boolean);
}

module.exports = {
  isPrivateOrReserved,
  fetchTorExitNodes,
  fetchFeodo,
  fetchUrlhausRecent,
  fetchThreatFox,
  fetchMalwareBazaarRecent,
  normalizeOtxIndicators,
};
