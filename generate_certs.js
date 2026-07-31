// Genera el par de certificados autofirmados del canal de sensores (HTTPS :8443).
//
// Uso:  node generate_certs.js [nombre-o-ip-extra ...]
//
// El certificado incluye SubjectAltName con localhost, el hostname del equipo y
// sus IPs locales. Sin SAN, un agente que conecte por IP (https://192.168.x.x:8443)
// falla la validación de hostname, que es justo lo que queremos que funcione.
const selfsigned = require('selfsigned');
const fs = require('fs');
const os = require('os');
const path = require('path');

const hostname = os.hostname();

// Direcciones IPv4 no internas de todas las interfaces.
const localIps = Object.values(os.networkInterfaces())
  .flat()
  .filter(i => i && i.family === 'IPv4' && !i.internal)
  .map(i => i.address);

const extra = process.argv.slice(2);
const isIp = (v) => /^\d{1,3}(\.\d{1,3}){3}$/.test(v);

const dnsNames = [...new Set(['localhost', hostname, ...extra.filter(v => !isIp(v))])];
const ipAddrs = [...new Set(['127.0.0.1', ...localIps, ...extra.filter(isIp)])];

const altNames = [
  ...dnsNames.map(value => ({ type: 2, value })),   // 2 = DNS
  ...ipAddrs.map(ip => ({ type: 7, ip })),          // 7 = IP
];

// selfsigned 5.x devuelve una promesa.
(async () => {
  const pems = await selfsigned.generate([{ name: 'commonName', value: hostname }], {
    days: 825,
    keySize: 2048,
    algorithm: 'sha256',
    extensions: [{ name: 'subjectAltName', altNames }],
  });

  // Junto al script, que es donde server.js los busca (no en el CWD).
  fs.writeFileSync(path.join(__dirname, 'server.cert'), pems.cert);
  fs.writeFileSync(path.join(__dirname, 'server.key'), pems.private);

  console.log('Certificados SSL generados (server.cert y server.key).');
  console.log(`  DNS: ${dnsNames.join(', ')}`);
  console.log(`  IP : ${ipAddrs.join(', ')}`);
  console.log(`  SHA-256: ${pems.fingerprint}`);
  console.log('\nCopia server.cert junto a agent/sensor.py en cada endpoint para que valide el canal.');
})().catch(err => {
  console.error('Error generando certificados:', err.message);
  process.exit(1);
});
