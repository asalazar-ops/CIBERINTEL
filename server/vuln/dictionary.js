// Diccionario curado nombre-comercial-Windows -> CPE 2.3. Es el corazón de la
// honestidad del módulo: NVD por keywordSearch/cpeName produce falsos
// positivos masivos (ver server/vuln/catalog.js para la evidencia), así que
// solo se correlacionan productos que un humano confirmó que mapean a un CPE
// real. Todo lo que no está aquí va a unmapped_software — nunca se reporta
// como "sin vulnerabilidades" por omisión.
const dbLayer = require('../db');

// Vendor:product verificados contra el CPE dictionary de NVD (GET
// /rest/json/cpes/2.0?keywordSearch=...). match_value se compara contra el
// DisplayName normalizado (lowercase, sin espacios extra, sin sufijos de
// arquitectura/versión). publisher_hint desempata homónimos cuando dos
// vendors usan un nombre de producto parecido.
const SEED_DICTIONARY = [
  { match_kind: 'prefix', match_value: 'google chrome', publisher_hint: 'google', cpe_vendor: 'google', cpe_product: 'chrome' },
  { match_kind: 'prefix', match_value: 'mozilla firefox', publisher_hint: 'mozilla', cpe_vendor: 'mozilla', cpe_product: 'firefox' },
  { match_kind: 'exact', match_value: '7-zip', publisher_hint: null, cpe_vendor: '7-zip', cpe_product: '7-zip' },
  { match_kind: 'prefix', match_value: 'notepad++', publisher_hint: null, cpe_vendor: 'don_ho', cpe_product: 'notepad\\+\\+' },
  { match_kind: 'prefix', match_value: 'microsoft edge', publisher_hint: 'microsoft', cpe_vendor: 'microsoft', cpe_product: 'edge' },
  { match_kind: 'prefix', match_value: 'vlc media player', publisher_hint: 'videolan', cpe_vendor: 'videolan', cpe_product: 'vlc_media_player' },
  { match_kind: 'prefix', match_value: 'winrar', publisher_hint: null, cpe_vendor: 'rarlab', cpe_product: 'winrar' },
  { match_kind: 'prefix', match_value: 'zoom', publisher_hint: 'zoom', cpe_vendor: 'zoom', cpe_product: 'zoom' },
  { match_kind: 'prefix', match_value: 'teamviewer', publisher_hint: null, cpe_vendor: 'teamviewer', cpe_product: 'teamviewer' },
  { match_kind: 'prefix', match_value: 'anydesk', publisher_hint: null, cpe_vendor: 'anydesk', cpe_product: 'anydesk' },
  { match_kind: 'prefix', match_value: 'python', publisher_hint: 'python software foundation', cpe_vendor: 'python', cpe_product: 'python' },
  { match_kind: 'prefix', match_value: 'node.js', publisher_hint: null, cpe_vendor: 'nodejs', cpe_product: 'node.js' },
  { match_kind: 'prefix', match_value: 'git', publisher_hint: 'the git development community', cpe_vendor: 'git', cpe_product: 'git' },
  { match_kind: 'prefix', match_value: 'putty', publisher_hint: null, cpe_vendor: 'putty', cpe_product: 'putty' },
  { match_kind: 'prefix', match_value: 'filezilla client', publisher_hint: null, cpe_vendor: 'filezilla-project', cpe_product: 'filezilla_client' },
  { match_kind: 'prefix', match_value: 'wireshark', publisher_hint: null, cpe_vendor: 'wireshark', cpe_product: 'wireshark' },
  { match_kind: 'prefix', match_value: 'microsoft visual studio code', publisher_hint: 'microsoft', cpe_vendor: 'microsoft', cpe_product: 'visual_studio_code' },
  { match_kind: 'prefix', match_value: 'openvpn', publisher_hint: null, cpe_vendor: 'openvpn', cpe_product: 'openvpn' },
  { match_kind: 'prefix', match_value: 'libreoffice', publisher_hint: null, cpe_vendor: 'libreoffice', cpe_product: 'libreoffice' },
  { match_kind: 'prefix', match_value: 'slack', publisher_hint: 'slack technologies', cpe_vendor: 'slack', cpe_product: 'slack' },
  { match_kind: 'prefix', match_value: 'docker desktop', publisher_hint: null, cpe_vendor: 'docker', cpe_product: 'docker_desktop' },
  { match_kind: 'prefix', match_value: 'oracle vm virtualbox', publisher_hint: 'oracle', cpe_vendor: 'oracle', cpe_product: 'vm_virtualbox' },
  { match_kind: 'prefix', match_value: 'adobe acrobat reader dc', publisher_hint: 'adobe', cpe_vendor: 'adobe', cpe_product: 'acrobat_reader_dc' },
  { match_kind: 'prefix', match_value: 'java', publisher_hint: 'oracle', cpe_vendor: 'oracle', cpe_product: 'jre' },
];

/**
 * Normaliza un DisplayName de Windows para matching: minúsculas, colapsa
 * espacios, quita sufijos de arquitectura y de versión pegada al nombre
 * (ej. "Google Chrome" desde "Google Chrome 120.0.6099.109").
 */
function normalizeProductName(rawName) {
  if (!rawName) return '';
  return rawName
    .toLowerCase()
    .replace(/\s*\((x64|x86|32-bit|64-bit)\)\s*/g, ' ')
    .replace(/\s+\d+(\.\d+){1,3}.*$/, '') // corta desde el primer número de versión suelto
    .replace(/\s+/g, ' ')
    .trim();
}

let _dictCache = null;
let _dictCacheAt = 0;
const DICT_CACHE_TTL_MS = 60_000;

async function loadDictionary() {
  const now = Date.now();
  if (_dictCache && now - _dictCacheAt < DICT_CACHE_TTL_MS) return _dictCache;
  _dictCache = await dbLayer.all('SELECT * FROM cpe_dictionary WHERE enabled = 1');
  _dictCacheAt = now;
  return _dictCache;
}

function invalidateDictionaryCache() {
  _dictCache = null;
}

/**
 * Empareja un {name, publisher} de software instalado contra el diccionario.
 * Devuelve {cpe_vendor, cpe_product, confidence} o null si no hay match —
 * "no match" es un resultado válido y esperado, no un error.
 */
async function matchToCpe(rawName, rawPublisher) {
  const normalized = normalizeProductName(rawName);
  if (!normalized) return null;
  const dict = await loadDictionary();

  // exact primero (más específico), luego prefix — y dentro de cada uno,
  // priorizar entradas con publisher_hint que coincida (desempata homónimos).
  const publisherNorm = (rawPublisher || '').toLowerCase();
  const candidates = dict.filter((e) => {
    if (e.match_kind === 'exact') return normalized === e.match_value;
    if (e.match_kind === 'prefix') return normalized.startsWith(e.match_value);
    return false;
  });
  if (!candidates.length) return null;

  candidates.sort((a, b) => {
    const aHint = a.publisher_hint && publisherNorm.includes(a.publisher_hint) ? 1 : 0;
    const bHint = b.publisher_hint && publisherNorm.includes(b.publisher_hint) ? 1 : 0;
    if (aHint !== bHint) return bHint - aHint;
    return a.match_kind === 'exact' ? -1 : 1;
  });

  const best = candidates[0];
  return { cpe_vendor: best.cpe_vendor, cpe_product: best.cpe_product, confidence: best.confidence || 'high' };
}

/** Siembra la tabla si está vacía — idempotente, seguro de llamar en cada arranque. */
async function seedDictionary() {
  const statements = SEED_DICTIONARY.map((e) => ({
    sql: `INSERT OR IGNORE INTO cpe_dictionary (match_kind, match_value, publisher_hint, cpe_vendor, cpe_product)
          VALUES (?, ?, ?, ?, ?)`,
    args: [e.match_kind, e.match_value, e.publisher_hint, e.cpe_vendor, e.cpe_product],
  }));
  await dbLayer.batch(statements);
  invalidateDictionaryCache();
}

module.exports = { normalizeProductName, matchToCpe, seedDictionary, loadDictionary, invalidateDictionaryCache, SEED_DICTIONARY };
