// Entrypoint serverless de Vercel. Toda petición a /api/* llega aquí (ver el
// rewrite en vercel.json) y Vercel invoca la app Express exportada por
// server/app.js como un handler (req, res) estándar de Node — Express es
// compatible con esa firma sin adaptadores adicionales.
module.exports = require('../server/app');
