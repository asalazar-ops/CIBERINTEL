// Autenticación del dashboard: un único usuario admin definido por variables de
// entorno (sin tabla `users` — no hay caso de uso multiusuario todavía). JWT en
// cookie HttpOnly firmada con AUTH_SECRET: stateless, así que funciona igual en
// un servidor local que en funciones serverless sin sesión compartida.
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const AUTH_SECRET = process.env.AUTH_SECRET || '';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || '';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '';
const COOKIE_NAME = 'cyberintel_session';
const TOKEN_TTL = '12h';

if (!AUTH_SECRET) {
  console.warn('\n⚠️  AUTH_SECRET no está definido en .env — el login del dashboard queda CERRADO.');
  console.warn('   Genera uno con:  node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"\n');
}
if (!ADMIN_EMAIL || !ADMIN_PASSWORD_HASH) {
  console.warn('\n⚠️  ADMIN_EMAIL / ADMIN_PASSWORD_HASH no están definidos en .env — nadie podrá iniciar sesión.');
  console.warn('   Genera el hash con: node server/hash_password.js "tu-contraseña"\n');
}

async function verifyCredentials(email, password) {
  if (!AUTH_SECRET || !ADMIN_EMAIL || !ADMIN_PASSWORD_HASH) return false;
  if (typeof email !== 'string' || typeof password !== 'string') return false;
  // Comparación de email en tiempo no crítico: no es el secreto, es un identificador.
  if (email.trim().toLowerCase() !== ADMIN_EMAIL.trim().toLowerCase()) return false;
  return bcrypt.compare(password, ADMIN_PASSWORD_HASH);
}

function issueSessionCookie(res, email) {
  const token = jwt.sign({ sub: email, role: 'admin' }, AUTH_SECRET, { expiresIn: TOKEN_TTL });
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 12 * 60 * 60 * 1000,
    path: '/',
  });
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, { path: '/' });
}

function readSession(req) {
  const token = req.cookies && req.cookies[COOKIE_NAME];
  if (!token || !AUTH_SECRET) return null;
  try {
    return jwt.verify(token, AUTH_SECRET);
  } catch {
    return null; // expirado, manipulado, o AUTH_SECRET rotado
  }
}

/** Protege las rutas del dashboard. Las de sensores/webhooks usan sus propios secretos. */
function requireAuth(req, res, next) {
  const session = readSession(req);
  if (!session) {
    return res.status(401).json({ error: 'Sesión inválida o expirada. Inicia sesión de nuevo.' });
  }
  req.user = session;
  next();
}

// Vercel invoca los cron jobs con `Authorization: Bearer $CRON_SECRET` cuando
// esa variable está configurada. Sin este chequeo, /api/cron/* — que hacen
// fetch a 15 feeds, refrescan OTX o escanean dominios de clientes — quedarían
// invocables por cualquiera que adivine la ruta, sin más autenticación.
const CRON_SECRET = process.env.CRON_SECRET || '';
if (!CRON_SECRET) {
  console.warn('\n⚠️  CRON_SECRET no está definido — los endpoints /api/cron/* quedan CERRADOS.');
  console.warn('   Generar con: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  console.warn('   y configurarlo también como variable de entorno en Vercel (la plataforma la usa automáticamente).\n');
}

function requireCronSecret(req, res, next) {
  const header = req.get('Authorization') || '';
  const received = header.startsWith('Bearer ') ? header.slice(7) : '';
  const a = Buffer.from(received);
  const b = Buffer.from(CRON_SECRET);
  const valid = CRON_SECRET.length > 0 && a.length === b.length && crypto.timingSafeEqual(a, b);
  if (!valid) {
    console.warn(`[AUTH] ⛔ Cron rechazado sin CRON_SECRET válido: ${req.path} desde ${req.ip}`);
    return res.status(403).json({ error: 'No autorizado' });
  }
  next();
}

module.exports = {
  verifyCredentials, issueSessionCookie, clearSessionCookie, readSession, requireAuth,
  requireCronSecret, COOKIE_NAME,
};
