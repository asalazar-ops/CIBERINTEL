// Genera el hash para ADMIN_PASSWORD_HASH.
// Uso: node server/hash_password.js "tu-contraseña"
const bcrypt = require('bcryptjs');

const password = process.argv[2];
if (!password) {
  console.error('Uso: node server/hash_password.js "tu-contraseña"');
  process.exit(1);
}

bcrypt.hash(password, 12).then((hash) => {
  console.log('\nAgrega esto a tu .env:\n');
  console.log(`ADMIN_PASSWORD_HASH=${hash}\n`);
});
