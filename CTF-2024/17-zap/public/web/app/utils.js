const { ecrecover, hashPersonalMessage, publicToAddress } = require('@ethereumjs/util')

function getBufferFromHex(hexString, byteLength) {
    if (hexString.length !== 2 + 2*byteLength) return
    const regex = new RegExp(`0x[0-9a-f]{${2 * byteLength}}`)
    if (!regex.test(hexString)) return
    const buffer = Buffer.from(`${hexString}`.slice(2), 'hex')
    if (buffer.length !== byteLength) return

    return buffer
}

function verifySignature(message, accountBuffer, signatureBuffer) {
    try {
        const hash = hashPersonalMessage(Buffer.from(message))
        const sigR = signatureBuffer.subarray(0, 32)
        const sigS = signatureBuffer.subarray(32, 64)
        const sigV = BigInt(`0x${signatureBuffer.subarray(64, 65).toString('hex')}`)

        const publicKey = ecrecover(hash, sigV, sigR, sigS)
        const accountBuffer2 = publicToAddress(publicKey)

        return !accountBuffer.compare(accountBuffer2)
    } catch (err) {
        return false
    }
}

function runQuery(db, query) {
    return new Promise((resolve, reject) => {
        try {
            db.all(query, [], (err, rows) => {
                if (err) return reject(err)
                resolve(rows)
            })
        } catch (err) {
            return reject(err)
        }
    })
}

module.exports = {
    getBufferFromHex,
    verifySignature,
    runQuery
}
