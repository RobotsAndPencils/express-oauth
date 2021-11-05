module.exports = (test, dependencies) => {
  'use strict'

  const { ExpressOAuth, cookie } = dependencies

  const itShouldNotThrow = (expect) => (err) => {
    expect(err, 'to equal', null)
  }

  const itShouldOverwriteTheCookie = (expect) => (err, actual) => {
    expect(err, 'to equal', null)
    expect(actual.headers.length, 'to equal', 2)
    const header = actual.headers[1]

    expect(header.original.name, 'to equal', 'Set-Cookie')
    expect(header.original.header, 'to contain', 'expired')
    expect(header.original.header, 'to contain', 'Secure;')
    expect(header.original.header, 'to contain', 'HttpOnly;')
    expect(header.parsed.slack_oauth, 'to be a', 'string')
    expect(header.parsed, 'to satisfy', {
      'Max-Age': '-99999999',
      SameSite: 'Lax',
      Path: '/',
    })
  }

  return test('given express-oauth', {
    'when verifyState is called': {
      when: async () => {
        const res = { actual: { headers: [] } }
        res.setHeader = (name, header) => {
          res.actual.headers.push({
            original: { name, header },
            parsed: cookie.parse(header),
          })
        }
        const { makeState, verifyState } = new ExpressOAuth({ secret: '71abbd66c08f49e7b7493b6912397782' })
        const { synchronizer } = await makeState()({}, res)

        const req = {
          query: { state: synchronizer },
          get: () => res.actual.headers[0].original.header,
        }
        await verifyState(req, res)

        return { ...res.actual, ...{ synchronizer } }
      },
      'it should not throw': itShouldNotThrow,
      'it should overwrite the cookie': itShouldOverwriteTheCookie,
      'and data was passed to be included in the jwt (object)': {
        when: async () => {
          const res = { actual: { headers: [] } }
          res.setHeader = (name, header) => {
            res.actual.headers.push({
              original: { name, header },
              parsed: cookie.parse(header),
            })
          }
          const expectedData = { foo: 'bar', bar: 'baz' }
          const { makeState, verifyState } = new ExpressOAuth({ secret: '71abbd66c08f49e7b7493b6912397782' })
          const { synchronizer } = await makeState(expectedData)({}, res)

          const req = {
            query: { state: synchronizer },
            get: () => res.actual.headers[0].original.header,
          }
          const tokenBody = await verifyState(req, res)

          return { ...res.actual, ...{ synchronizer, tokenBody, expectedData } }
        },
        'it should not throw': itShouldNotThrow,
        'it should overwrite the cookie': itShouldOverwriteTheCookie,
        'it should return the data argument': (expect) => (err, actual) => {
          expect(err, 'to equal', null)
          expect(actual.tokenBody.data, 'to equal', actual.expectedData)
          expect(actual.tokenBody.synchronizer, 'to equal', actual.synchronizer)
        },
      },
      'and data was passed to be included in the jwt (primitive)': {
        when: async () => {
          const res = { actual: { headers: [] } }
          res.setHeader = (name, header) => {
            res.actual.headers.push({
              original: { name, header },
              parsed: cookie.parse(header),
            })
          }
          const expectedData = 'foo'
          const { makeState, verifyState } = new ExpressOAuth({ secret: '71abbd66c08f49e7b7493b6912397782' })
          const { synchronizer } = await makeState(expectedData)({}, res)

          const req = {
            query: { state: synchronizer },
            get: () => res.actual.headers[0].original.header,
          }
          const tokenBody = await verifyState(req, res)

          return { ...res.actual, ...{ synchronizer, tokenBody, expectedData } }
        },
        'it should not throw': itShouldNotThrow,
        'it should overwrite the cookie': itShouldOverwriteTheCookie,
        'it should return the data argument': (expect) => (err, actual) => {
          expect(err, 'to equal', null)
          expect(actual.tokenBody.data, 'to equal', actual.expectedData)
          expect(actual.tokenBody.synchronizer, 'to equal', actual.synchronizer)
        },
      },
      'and the cookie is missing': {
        when: async () => {
          const res = { actual: { headers: [] } }
          res.setHeader = (name, header) => {
            res.actual.headers.push({
              original: { name, header },
              parsed: cookie.parse(header),
            })
          }
          const { makeState, verifyState } = new ExpressOAuth({ secret: '71abbd66c08f49e7b7493b6912397782' })
          const { synchronizer } = await makeState()({}, res)

          const req = {
            query: { state: synchronizer },
            get: () => undefined,
          }
          await verifyState(req, res)

          return { ...res.actual, ...{ synchronizer } }
        },
        'it should throw': (expect) => (err) => {
          expect(err, 'not to equal', null)
        },
      },
      'and the cookie is signed with a different secret (or is otherwise not valid)': {
        when: async () => {
          const res = { actual: { headers: [] } }
          res.setHeader = (name, header) => {
            res.actual.headers.push({
              original: { name, header },
              parsed: cookie.parse(header),
            })
          }
          const { makeState } = new ExpressOAuth({ secret: '0ca9d33e-2ee5-42e7-b95f-7c1af3cff152' })
          const { verifyState } = new ExpressOAuth({ secret: '71abbd66c08f49e7b7493b6912397782' })
          const { synchronizer } = await makeState()({}, res)

          const req = {
            query: { state: synchronizer },
            get: () => res.actual.headers[0].original.header,
          }
          await verifyState(req, res)

          return { ...res.actual, ...{ synchronizer } }
        },
        'it should throw': (expect) => (err) => {
          expect(err, 'not to equal', null)
        },
      },
      'and the query isn\'t parsed': {
        when: async () => {
          const res = { actual: { headers: [] } }
          res.setHeader = (name, header) => {
            res.actual.headers.push({
              original: { name, header },
              parsed: cookie.parse(header),
            })
          }
          const { makeState, verifyState } = new ExpressOAuth({ secret: '71abbd66c08f49e7b7493b6912397782' })
          await makeState()({}, res)

          const req = {
            get: () => res.actual.headers[0].original.header,
          }
          await verifyState(req, res)

          return res.actual
        },
        'it should throw': (expect) => (err) => {
          expect(err, 'not to equal', null)
        },
      },
      'and the synchronizer doesn\'t match (wrong buffer size)': {
        when: async () => {
          const res = { actual: { headers: [] } }
          res.setHeader = (name, header) => {
            res.actual.headers.push({
              original: { name, header },
              parsed: cookie.parse(header),
            })
          }
          const { makeState, verifyState } = new ExpressOAuth({ secret: '71abbd66c08f49e7b7493b6912397782' })
          await makeState()({}, res)

          const req = {
            query: { state: 'doesntmatch' },
            get: () => res.actual.headers[0].original.header,
          }
          await verifyState(req, res)

          return res.actual
        },
        'it should throw': (expect) => (err) => {
          expect(err, 'not to equal', null)
          expect(err.message, 'to equal', 'Input buffers must have the same byte length')
        },
      },
      'and the synchronizer doesn\'t match (different secret)': {
        when: async () => {
          const res = { actual: { headers: [] } }
          res.setHeader = (name, header) => {
            res.actual.headers.push({
              original: { name, header },
              parsed: cookie.parse(header),
            })
          }
          const oauth1 = new ExpressOAuth({ secret: '71abbd66c08f49e7b7493b6912397782' })
          const oauth2 = new ExpressOAuth({ secret: '81abbd66c08f49e7b7493b6912397783' })
          await oauth1.makeState()({}, res)

          const req = {
            query: { state: (await oauth2.makeState()({}, res).synchronizer) },
            get: () => res.actual.headers[0].original.header,
          }
          await oauth1.verifyState(req, res)

          return res.actual
        },
        'it should throw': (expect) => (err) => {
          expect(err, 'not to equal', null)
          expect(err.message, 'to equal', 'The OAuth state, and device state are not synchronized. Try again.')
        },
      },
    },
  })
}
