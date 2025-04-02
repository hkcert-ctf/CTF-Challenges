const express = require('express')
const path = require('path')
const bodyParser = require('body-parser')
const exphbs = require('express-handlebars')
const session = require('express-session')
const crypto = require('crypto')

const pages = require('./pages')
const api = require('./api')
const db = require('./db')
const { runQuery } = require('./utils')

const app = express()

const appSecret = crypto.randomBytes(16).toString('hex')
app.use(bodyParser.json())
app.use(session({ secret: appSecret }))

const hbs = exphbs.create({
    helpers: {
        'trim_address': function (address) {
            return `${address.substr(0, 6)}...${address.substr(38, 42)}`
        }
    }
})

app.engine('handlebars', hbs.engine)
app.set('view engine', 'handlebars')
app.set('views', path.join(__dirname, './views'))

app.use('/', pages)
app.use('/api', api)
app.use('/static', express.static(path.join(__dirname, 'static')))

app.listen(3000, async function () {
    // Initialize the database
    await runQuery(db, `CREATE TABLE users (account VARCHAR(42), deposit_nonce VARCHAR(16), transaction_nonce VARCHAR(16), balance INT)`)
    await runQuery(db, `CREATE TABLE transactions (from_account VARCHAR(42), to_account VARCHAR(42), amount INT, time TIMESTAMP)`)

    const depositNonce = crypto.randomBytes(8).toString('hex')
    const transactionNonce = crypto.randomBytes(8).toString('hex')
    await runQuery(db, `INSERT INTO users (account, deposit_nonce, transaction_nonce, balance) VALUES ('${process.env.SERVICE_WALLET_ACCOUNT}', '${depositNonce}', '${transactionNonce}', '1000000000000000000')`)

    console.log('server is listening on port 3000')
})
