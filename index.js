const blueprint = require('@polyn/blueprint')
const immutable = require('@polyn/immutable')
const cookie = require('cookie')
const crypto = require('crypto')
const jsonwebtoken = require('jsonwebtoken')

const { makeState } = require('./src/make-state')({ cookie, crypto, jsonwebtoken })
const { verifyState } = require('./src/verify-state')({ cookie, crypto, jsonwebtoken })
const { ExpressOAuth } = require('./src/ExpressOAuth')({ blueprint, immutable, makeState, verifyState })

module.exports = { ExpressOAuth }
