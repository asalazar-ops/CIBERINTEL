// ─────────────────────────────────────────────────────────────────────────────
// CyberIntel EC — Arranque local (dos puertos: dashboard + sensores).
// La lógica de negocio vive en server/app.js, que solo exporta la app Express
// sin abrir ningún puerto. En Vercel, api/index.js importa esa misma app y la
// sirve como función serverless — este archivo no se usa en producción.
// ─────────────────────────────────────────────────────────────────────────────
const fs = require('fs');
const path = require('path');
const https = require('https');
const app = require('./server/app');

// ─── INICIAR SERVIDOR HTTPS PARA SENSORES ────────────────────────────────────
const HTTPS_PORT = 8443;
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
// Escucha sólo en loopback: la API del dashboard no tiene autenticación de red
// propia (solo de sesión), así que no debe estar accesible desde la LAN.
// Los sensores usan el canal HTTPS :8443.
const PORT = 3001;
app.listen(PORT, '127.0.0.1', () => {
  console.log('\n🛡️  CyberIntel EC — Servidor RSS local (Con Histórico)');
  console.log(`📡 Corriendo en: http://127.0.0.1:${PORT} (sólo local)`);
});
