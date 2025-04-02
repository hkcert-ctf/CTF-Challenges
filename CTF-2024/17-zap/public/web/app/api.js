const axios = require('axios')
const { Router } = require('express')
const crypto = require('crypto')

const db = require('./db')
const { authenticate } = require('./middlewares')
const { getBufferFromHex, verifySignature, runQuery } = require('./utils')

const router = Router()

router.post('/login', async function (req, res) {
    try {
        const { account, signature } = req.body

        const accountBuffer = getBufferFromHex(account, 20)
        if (!accountBuffer) {
            return res.status(400).json({ 'error': 'Invalid account format' })
        }
        const signatureBuffer = getBufferFromHex(signature, 65)
        if (!signatureBuffer) {
            return res.status(400).json({ 'error': 'Invalid signature format' })
        }
        const message = `I am ${account} and I am signing in`
        if (!verifySignature(message, accountBuffer, signatureBuffer)) {
            return res.status(400).json({ 'error': 'Invalid signature' })
        }

        const [{ count: duplicateUsernameCount }] = await runQuery(db, `SELECT COUNT(*) as count FROM users WHERE account = '${account}'`)
        if (duplicateUsernameCount === 0) {
            const depositNonce = crypto.randomBytes(8).toString('hex')
            const transactionNonce = crypto.randomBytes(8).toString('hex')
            await runQuery(db, `INSERT INTO users (account, deposit_nonce, transaction_nonce, balance) VALUES ('${account}', '${depositNonce}', '${transactionNonce}', 0)`)
            await runQuery(db, `INSERT INTO transactions (from_account, to_account, amount, time) VALUES ('${process.env.SERVICE_WALLET_ACCOUNT}', '${account}', '0', strftime('%Y-%m-%dT%H:%M:%SZ','now'))`)
        }
        req.session.account = account

        return res.status(200).json({})
    } catch (err) {
        return res.status(500).json({ 'error': 'Unknown error.' })
    }
})

router.get('/me', authenticate, async function (req, res) {
    try {
        const account = req.session.account

        const [[{ deposit_nonce: depositNonce, transaction_nonce: transactionNonce, balance }], preformattedTransactions] = await Promise.all([
            runQuery(db, `SELECT deposit_nonce, transaction_nonce, balance FROM users WHERE account = '${account}'`),
            runQuery(db, `SELECT from_account, to_account, amount, time FROM transactions WHERE from_account = '${account}' OR to_account = '${account}' ORDER BY time DESC LIMIT 50`)
        ])

        const transactions = preformattedTransactions.map(tx => ({
            amount: tx['amount'],
            time: tx['time'],
            from: tx['from_account'],
            to: tx['to_account']
        }))
        return res.status(200).json({
            account,
            deposit_nonce: `[⚡] ${depositNonce}`,
            transaction_nonce: transactionNonce,
            balance,
            transactions
        })
    } catch (err) {
        return res.status(500).json({ 'error': 'Unknown error.' })
    }
})

router.post('/transfer', authenticate, async function (req, res) {
    try {
        const { to_account: toAccount, amount, signature } = req.body
        const fromAccount = req.session.account

        const fromAccountBuffer = getBufferFromHex(fromAccount, 20)
        if (!fromAccountBuffer) {
            return res.status(400).json({ 'error': 'Invalid account format.' })
        }
        const signatureBuffer = getBufferFromHex(signature, 65)
        if (!signatureBuffer) {
            return res.status(400).json({ 'error': 'Invalid signature format.' })
        }
        const toAccountBuffer = getBufferFromHex(toAccount, 20)
        if (!toAccountBuffer) {
            return res.status(400).json({ 'error': 'Invalid account format.' })
        }

        const amountInWei = BigInt(amount * 10**18)
        if (amountInWei <= 0) {
            return res.status(400).json({ 'error': 'You must send a positive amount of Ethers.' })
        }
        const [{ balance: fromBalance, transaction_nonce: nonce }] = await runQuery(db, `SELECT balance, transaction_nonce FROM users WHERE account = '${fromAccount}'`)
        if (amountInWei > fromBalance) {
            return res.status(400).json({ 'error': "You don't have enough funds." })
        }
        const message = `I am ${fromAccount} and I am transferring ${amount} ETH to ${toAccount} (nonce: ${nonce})`
        if (!verifySignature(message, fromAccountBuffer, signatureBuffer)) {
            return res.status(400).json({ 'error': 'Invalid signature.' })
        }

        const [{ count: toCount }] = await runQuery(db, `SELECT COUNT(*) as count FROM users WHERE account = '${toAccount}'`)
        if (toCount === 0) {
            return res.status(400).json({ 'error': 'The recipient has not registered to ⚡.' })
        }
        
        const newNonce = crypto.randomBytes(8).toString('hex')
        await runQuery(db, `UPDATE users SET balance = balance - ${amountInWei}, transaction_nonce = '${newNonce}' WHERE account = '${fromAccount}'`)
        await runQuery(db, `UPDATE users SET balance = balance + ${amountInWei} WHERE account = '${toAccount}'`)
        await runQuery(db, `INSERT INTO transactions (from_account, to_account, amount, time) VALUES (
            '${fromAccount}', '${toAccount}', '${amountInWei}', strftime('%Y-%m-%dT%H:%M:%SZ','now')
        )`)

        truncatedToAccount = `${toAccount.substr(0, 6)}...${toAccount.substr(38, 42)}`
        return res.status(200).json({ 'message': `You successfully transfered ${Number(amount).toFixed(5)} ETH to ${truncatedToAccount}.`})
    } catch (err) {
        return res.status(500).json({ 'error': 'Unknown error.' })
    }
})

// No, there are no bugs I intend to inject here. I just want to earn some
// Ethers if you guys decided to pay to win :) Feel free to disregard this
// API... Anyways, I am happier if you use this API.
router.post('/deposit', authenticate, async function (req, res) {
    try {
        const { 'transaction_id': transactionId } = req.body
        const account = req.session.account

        const regex = new RegExp(`0x[0-9a-f]{64}`)
        if (!regex.test(transactionId)) {
            return res.status(400).json({ 'error': 'Invalid transaction id.' })
        }
        const [{ deposit_nonce: nonce }] = await runQuery(db, `SELECT deposit_nonce FROM users WHERE account = '${account}'`)

        const { data: { result } } = await axios.post(`https://mainnet.infura.io/v3/${process.env.INFURA_API_KEY}`, {
            jsonrpc: '2.0',
            method: 'eth_getTransactionByHash',
            params: [transactionId],
            id: 1
        })

        if (!result) {
            return res.status(400).json({ 'error': 'Transaction not found on mainnet.' })
        }
        if (result.from !== account) {
            return res.status(400).json({ 'error': 'You should be the sender for this transaction.' })
        }
        if (result.to !== process.env.SERVICE_WALLET_ACCOUNT) {
            return res.status(400).json({ 'error': 'The recipient for this transaction is incorrect.' })
        }
        const formattedNonce = `0x${Buffer.from(`[⚡] ${nonce}`).toString('hex')}`
        if (result.input !== formattedNonce) {
            return res.status(400).json({ 'error': 'The nonce for this transaction is incorrect.' })
        }
        if (BigInt(result.value) < BigInt('1000000000000000000')) {
            return res.status(400).json({ 'error': 'The amount of the transaction should be not less than 1 ETH.' })
        }

        const { data: { result: currentBlockNumber } } = await axios.post(`https://mainnet.infura.io/v3/${process.env.INFURA_API_KEY}`, {
            jsonrpc: '2.0',
            method: 'eth_blockNumber',
            params: [],
            id: 1
        })
        const confirmedBlocks = BigInt(currentBlockNumber) - BigInt(result.blockNumber)
        if (confirmedBlocks < 12) {
            return res.status(400).json({ 'error': 'Please wait until there are 12 confirmed blocks.' })
        }

        const newNonce = crypto.randomBytes(8).toString('hex')
        await runQuery(db, `UPDATE users SET balance = balance + ${BigInt(result.value)}, deposit_nonce = '${newNonce}' WHERE account = '${account}'`)

        return res.status(200).json({ 'message': `You successfully deposited ${(result.value / 10**18).toFixed(5)} ETH to ⚡.`})
    } catch (err) {
        return res.status(500).json({ 'error': 'Unknown error.' })
    }
})

router.post('/withdraw', authenticate, async function (req, res) {
    try {
        const { amount, signature } = req.body
        const account = req.session.account

        const accountBuffer = getBufferFromHex(account, 20)
        const signatureBuffer = getBufferFromHex(signature, 65)
        if (!signatureBuffer) {
            return res.status(400).json({ 'error': 'Invalid signature format.' })
        }

        const [{ transaction_nonce: nonce }] = await runQuery(db, `SELECT transaction_nonce FROM users WHERE account = '${account}'`)
        const message = `I am ${account} and I am withdrawing ${amount} ETH (nonce: ${nonce})`
        if (!verifySignature(message, accountBuffer, signatureBuffer)) {
            return res.status(400).json({ 'error': 'Invalid signature.' })
        }

        const amountInWei = BigInt(amount * 10**18)
        const [{ balance }] = await runQuery(db, `SELECT balance FROM users WHERE account = '${account}'`)
        if (amountInWei <= 0) {
            return res.status(400).json({ 'error': 'You must withdraw a positive amount of Ethers.' })
        }
        if (amountInWei > balance) {
            return res.status(400).json({ 'error': "You don't have enough funds." })
        }

        const newNonce = crypto.randomBytes(8).toString('hex')
        await runQuery(db, `UPDATE users SET balance = balance - ${amountInWei}, transaction_nonce = '${newNonce}' WHERE account = '${account}'`)

        // "You successfully withdrew..."? No, I don't want to release money I just earned :)
        if (amountInWei < BigInt(10e18)) {
            return res.status(200).json({ 'message': `You successfully withdrew ${amount} ETH.`})
        } else {
            return res.status(200).json({ 'message': `You successfully withdrew ${amount} ETH. We are sending the flag to thank your continuous support to ⚡: ${process.env.FLAG}.`})
        }
    } catch (err) {
        return res.status(500).json({ 'error': 'Unknown error.' })
    }
})

module.exports = router
