module.exports = (test, dependencies) => {
  'use strict'

  const { ExpressOAuth } = dependencies

  return test('given express-oauth', {
    'when an instance of ExpressOAuth is created': {
      'without a secret': {
        when: () => new ExpressOAuth(),
        'it should throw': (expect) => (err) => {
          expect(err, 'not to be', null)
          expect(err.message, 'to contain', 'expected `secret` {undefined} to be a {string}')
        },
      },
      'with a secret of less than 32 chars': {
        when: () => new ExpressOAuth({ secret: 'short' }),
        'it should throw': (expect) => (err) => {
          expect(err, 'not to be', null)
          expect(err.message, 'to contain', '256 or more bits')
        },
      },
      'with only a secret': {
        when: () => new ExpressOAuth({ secret: '71abbd66c08f49e7b7493b6912397782' }),
        'it should use defaults for the other options': (expect) => (err, actual) => {
          expect(err, 'to equal', null)
          expect(actual.options, 'to satisfy', {
            cookieName: 'slack_oauth',
            maxAgeSeconds: 180,
            expiresIn: '180s',
          })
        },
      },
      'with all the things': {
        when: () => new ExpressOAuth({
          secret: '71abbd66c08f49e7b7493b6912397782',
          cookieName: 'test',
          maxAgeSeconds: 60,
        }),
        'it should use the given options': (expect) => (err, actual) => {
          expect(err, 'to equal', null)
          expect(actual.options, 'to satisfy', {
            cookieName: 'test',
            maxAgeSeconds: 60,
            expiresIn: '60s',
          })
        },
      },
    },
  })
}
