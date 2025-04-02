const { Router } = require('express')
const { authenticatePages } = require('./middlewares')

const router = Router()

router.get('/', async function (req, res) {
    return res.render('home', {
        account: req.session.account
    })
})

router.get('/trade', authenticatePages, async function (req, res) {
    return res.render('trade', {
        serviceAccount: process.env.SERVICE_WALLET_ACCOUNT,
        account: req.session.account
    })
})

router.get('/logout', authenticatePages, async function (req, res) {
    req.session.destroy()
    return res.redirect('/')
})

module.exports = router
