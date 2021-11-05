/**
 * @param {@polyn/blueprint} blueprint
 * @param {@polyn/immutable} immutable
 * @param {makeState} makeState
 * @param {verifyState} verifyState
 */
function ExpressOAuthFactory (deps) {
  'use strict'

  const { is, optional, registerValidator, required } = deps.blueprint
  const { immutable } = deps.immutable

  registerValidator('256bitString', ({ key, value }) => {
    if (
      typeof value === 'string' &&
      Buffer.byteLength(value.trim(), 'utf8') >= 32 // 32 utf8 chars = 256 bits
    ) {
      return { value }
    }

    return { err: new Error(`expected \`${key}\` {${is.getType(value)}} to be a {string} of 256 or more bits (32 or more utf8 chars)`) }
  })

  const ExpressOAuthOptions = immutable('ExpressOAuthOptions', {
    secret: '256bitString',
    cookieName: optional('string').withDefault('slack_oauth'),
    maxAgeSeconds: optional('number').withDefault(180 /* 3 minutes */),
    expiresIn: required('string').from(({ output }) => `${output.maxAgeSeconds}s`),
  })

  /**
   * @param {string} secret - a 256 bit (32 utf-8 char) or greater string to sign the jwt with
   * @param {string} cookieName - a name for the cookie that will synchronize the User Agent
   * @param {number} maxAgeSeconds - the time to live in seconds for the cookie, and jwt token
   */
  function ExpressOAuth (input) {
    const options = new ExpressOAuthOptions(input)
    const makeState = deps.makeState(options)
    const verifyState = deps.verifyState(options)

    return { makeState, verifyState, options }
  }

  return { ExpressOAuth }
}

module.exports = ExpressOAuthFactory
