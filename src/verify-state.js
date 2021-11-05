/**
 * @param {crypto} crypto
 * @param {jsonwebtoken} jsonwebtoken
 * @param {cookie} cookie
 */
function VerifyStateFactory (deps) {
  'use strict'

  const { timingSafeEqual } = deps.crypto
  const { verify } = deps.jsonwebtoken
  const { cookie } = deps

  /**
   * Verifies that the OAuth "state" parameter, and the User Agent session
   * are synchronized, and destroys the User Agent session, which should be a nonce
   * @see https://tools.ietf.org/html/rfc6819#section-5.3.5
   * @curried
   * @param {string} cookieName - a name for the cookie
   * @param {string} secret - a secret to sign the JWT with
   * @param {Request} req - the express request
   * @param {Response} res - the express response
   * @throws {Error} if the User Agent session state is invalid, or if the
   *   OAuth "state" parameter, and the state found in the User Agent session
   *   do not match
   */
  const verifyState = (input) => async (req, res) => {
    const { cookieName, secret } = input

    if (typeof req.query !== 'object' || typeof req.query.state !== 'string') {
      throw new Error('The OAuth state, and device state are not synchronized. Try again.')
    }

    /**
     * Get the state that was returned from Slack
     */
    const state = req.query.state

    /*
     * Get the cookie header, if it exists
     */
    const cookies = cookie.parse(req.get('cookie') || '')

    /*
     * Remove the User Agent session - it should be a nonce
     */
    res.setHeader('Set-Cookie', cookie.serialize(cookieName, 'expired', {
      maxAge: -99999999, // set the cookie to expire in the past
      sameSite: 'lax', // limit the scope of the cookie to this site, but allow top level redirects
      path: '/', // set the relative path that the cookie is scoped for
      secure: true, // only support HTTPS connections
      httpOnly: true, // dissallow client-side access to the cookie
      overwrite: true, // overwrite the cookie every time, so nonce data is never re-used
    }))

    /*
     * Verify that the User Agent session was signed by this server, and
     * decode the session
     */
    const tokenBody = await verify(cookies[cookieName], secret)
    const { synchronizer } = tokenBody

    /*
     * Verify that the value in the OAuth "state" parameter, and in the
     * User Agent session are equal, and prevent timing attacks when
     * comparing the values
     */
    if (!timingSafeEqual(Buffer.from(synchronizer), Buffer.from(state))) {
      throw new Error('The OAuth state, and device state are not synchronized. Try again.')
    }

    return tokenBody
  }

  return { verifyState }
}

module.exports = VerifyStateFactory
