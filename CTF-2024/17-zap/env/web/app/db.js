const sqlite3 = require('sqlite3')

const db = new sqlite3.Database(':memory:')

module.exports = db
