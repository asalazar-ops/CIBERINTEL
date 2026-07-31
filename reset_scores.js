const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const db = new sqlite3.Database(path.join(__dirname, 'sensors.db'), (err) => {
  if (err) {
    console.error('Error:', err.message);
    process.exit(1);
  }
  db.run(`UPDATE sensor_behavior_scores SET current_score = 0, status = 'low'`, (err) => {
    if (err) console.error('Error updating:', err.message);
    else console.log('✅ Scores reset to 0.');
    db.close();
  });
});
