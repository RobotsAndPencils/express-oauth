/**
 * @param {crypto} crypto
 * @param {jsonwebtoken} jsonwebtoken
 * @param {cookie} cookie
 */
function MakeStateFactory (deps) {
  'use strict'

  const { randomBytes } = deps.crypto
  const { sign } = deps.jsonwebtoken
  const { cookie } = deps

  /**
  * Generates a value that will be used to link the OAuth "state" parameter
  * to User Agent (device) session.
  * @see https://tools.ietf.org/html/rfc6819#section-5.3.5
  * @curried
  * @param {string} cookieName - a name for the cookie
  * @param {string} secret - a secret to sign the JWT with
  * @param {number} maxAgeSeconds - the time to live in seconds for the cookie
  * @param {string} expiresIn - the time to live for the JWT
  * @param {object} data - optional data to add to the JWT
  * @param {Request} req - the express request
  * @param {Response} res - the express response
  * @return {{ synchronizer: string; }} - the value to be sent in the OAuth "state" parameter
  */
  const makeState = (input) => (data) => async (req, res) => {
    const { cookieName, secret, maxAgeSeconds, expiresIn } = input

    /*
    * generate an unguessable value that will be used in the OAuth "state"
    * parameter, as well as in the User Agent
    */
    const synchronizer = randomBytes(16).toString('hex')
    const tokenBody = { synchronizer, data }

    /*
    * Create, and sign the User Agent session state
    */
    const jwt = await sign(
      tokenBody,
      secret,
      { expiresIn },
    )

    /*
    * Add the User Agent session state to an http-only, secure, samesite cookie
    */
    res.setHeader('Set-Cookie', cookie.serialize(cookieName, jwt, {
      maxAge: maxAgeSeconds, // will expire in 3 minutes
      sameSite: 'lax', // limit the scope of the cookie to this site, but allow top level redirects
      path: '/', // set the relative path that the cookie is scoped for
      secure: true, // only support HTTPS connections
      httpOnly: true, // dissallow client-side access to the cookie
      overwrite: true, // overwrite the cookie every time, so nonce data is never re-used
    }))

    /**
    * Return the value to be used in the OAuth "state" parameter
    * NOTE that this should not be the same, as the signed session state.
    * If you prefer the OAuth session state to also be a JWT, sign it with
    * a separate secret
    */
    return { jwt, ...tokenBody }
  } // /makeState

  return { makeState }
}

module.exports = MakeStateFactory
