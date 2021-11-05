module.exports = (test, dependencies) => {
  'use strict'

  const { ExpressOAuth, cookie } = dependencies

  const itShouldGenerateSynchronizer = (expect) => (err, actual) => {
    expect(err, 'to equal', null)
    expect(actual.synchronizer, 'to be a', 'string')
  }

  const itShouldReturnAJwt = (expect) => (err, actual) => {
    expect(err, 'to equal', null)
    expect(actual.jwt, 'to be a', 'string')
  }

  const itShouldSetCookie = (expect) => (err, actual) => {
    expect(err, 'to equal', null)
    expect(actual.headers.length, 'to equal', 1)
    const header = actual.headers[0]

    expect(header.original.name, 'to equal', 'Set-Cookie')
    expect(header.original.header, 'to contain', 'Secure;')
    expect(header.original.header, 'to contain', 'HttpOnly;')
    expect(header.parsed.slack_oauth, 'to be a', 'string')
    expect(header.parsed, 'to satisfy', {
      'Max-Age': '180',
      SameSite: 'Lax',
      Path: '/',
    })
  }

  return test('given express-oauth', {
    'when makeState is called _with_ a data argument (object)': {
      when: async () => {
        const res = { actual: { headers: [] } }
        res.setHeader = (name, header) => {
          res.actual.headers.push({ original: { name, header }, parsed: cookie.parse(header) })
        }
        const { makeState } = new ExpressOAuth({ secret: '71abbd66c08f49e7b7493b6912397782' })
        const expectedData = { foo: 'bar', bar: 'baz' }
        const { jwt, synchronizer, data } = await makeState(expectedData)({}, res)
        return { ...res.actual, ...{ jwt, synchronizer, data }, expectedData }
      },
      'it should generate a synchronizer token': itShouldGenerateSynchronizer,
      'it should return the jwt': itShouldReturnAJwt,
      'it should return the data argument': (expect) => (err, actual) => {
        expect(err, 'to equal', null)
        expect(actual.data.foo, 'to equal', actual.expectedData.foo)
        expect(actual.data.bar, 'to equal', actual.expectedData.bar)
      },
      'it should add a secure, http-only cookie to the headers': itShouldSetCookie,
    },
    'when makeState is called _with_ a data argument (primitive)': {
      when: async () => {
        const res = { actual: { headers: [] } }
        res.setHeader = (name, header) => {
          res.actual.headers.push({ original: { name, header }, parsed: cookie.parse(header) })
        }
        const { makeState } = new ExpressOAuth({ secret: '71abbd66c08f49e7b7493b6912397782' })
        const expectedData = 'foo'
        const { jwt, synchronizer, data } = await makeState(expectedData)({}, res)
        return { ...res.actual, ...{ jwt, synchronizer, data }, expectedData }
      },
      'it should generate a synchronizer token': itShouldGenerateSynchronizer,
      'it should return the jwt': itShouldReturnAJwt,
      'it should return the data argument': (expect) => (err, actual) => {
        expect(err, 'to equal', null)
        expect(actual.data, 'to equal', actual.expectedData)
      },
      'it should add a secure, http-only cookie to the headers': itShouldSetCookie,
    },
    'when makeState is called _without_ a data argument': {
      when: async () => {
        const res = { actual: { headers: [] } }
        res.setHeader = (name, header) => {
          res.actual.headers.push({ original: { name, header }, parsed: cookie.parse(header) })
        }
        const { makeState } = new ExpressOAuth({ secret: '71abbd66c08f49e7b7493b6912397782' })
        const { jwt, synchronizer } = await makeState()({}, res)
        return { ...res.actual, ...{ jwt, synchronizer } }
      },
      'it should generate a synchronizer token': itShouldGenerateSynchronizer,
      'it should return the jwt': itShouldReturnAJwt,
      'it should add a secure, http-only cookie to the headers': itShouldSetCookie,
    },
  })
}
