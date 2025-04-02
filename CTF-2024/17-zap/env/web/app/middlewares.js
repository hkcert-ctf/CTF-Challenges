async function authenticate(req, res, next) {
    if (!req.session.account) {
        return res.status(401).json({ 'error': 'not signed in' })
    }
    next()
}

async function authenticatePages(req, res, next) {
    if (!req.session.account) {
        return res.redirect('/')
    }
    next()
}

module.exports = { authenticate, authenticatePages }
