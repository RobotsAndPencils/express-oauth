# express-oauth

[![tests](https://github.com/RobotsAndPencils/express-oauth/actions/workflows/pr-check.yml/badge.svg)](https://github.com/RobotsAndPencils/express-oauth/actions/workflows/pr-check.yml)
[![Coverage Status](https://coveralls.io/repos/github/RobotsAndPencils/express-oauth/badge.svg?branch=main)](https://coveralls.io/github/RobotsAndPencils/express-oauth?branch=main)


`@robotsandpencils/express-oauth` is an express middleware for mitigating CSRF attacks in OAuth 2.0 flows. It is not intended to be used on it's own. Examples follow for leveraging this package to produce more specific OAuth middleware.

## Usage

```Shell
npm install --save @robotsandpencils/express-oauth
```

```javascript
const { ExpressOAuth } = require('@robotsandpencils/express-oauth')
const { App, ExpressReceiver } = require('@slack/bolt')
const { WebClient } = require('@slack/web-api')
const qs = require('qs')

const { makeState, verifyState } = new ExpressOAuth({
  secret: process.env.OAUTH_SECRET, // minimum 256 bit string (i.e. 32 char utf8 string)
})

const receiver = new ExpressReceiver({
  signingSecret: process.env.SLACK_SIGNING_SECRET,
})
const app = receiver.app
const bolt = new App({
  receiver,
  authorize: async (ctx) => { /* ... */ },
  convoStore: false,
})

const authorizePath = '/slack/install/authorize'
const verifyPath = '/slack/install/verify'

app.get(authorizePath, async (req, res, next) => {
  const data = { foo: 'bar' } // state data we want to use when oauth is complete
  const { synchronizer } = await makeState(data)(req, res)
  const queryObject = {
    client_id: process.env.SLACK_CLIENT_ID,
    response_type: 'code',
    response_mode: 'query',
    redirect_uri: `https://${req.get('host')}${verifyPath}`,
    scope: ['app_mentions:read', 'chat:write', 'commands', 'users:read'],
    state: synchronizer,
  }

  const query = qs.stringify(queryObject)
  const redirectURL = `https://slack.com/oauth/v2/authorize?${query}`

  /*
    * NOTE that this redirects the client to Slack immediately because
    * the OAuth flow is time sensitive (only valid for 3 minutes in this example)
    */
  const htmlResponse = '<html>' +
    `\n<meta http-equiv="refresh" content="0; URL=${redirectURL}">` +
    '\n<body>' +
    '\n  <h1>Success! Redirecting to the Slack App...</h1>' +
    `\n  <button onClick="window.location = '${redirectURL}'">Click here to redirect</button>` +
    '\n</body></html>'
  res.writeHead(200, { 'Content-Type': 'text/html' })
  res.end(htmlResponse)
})

app.get(verifyPath, async (req, res, next) => {
  const { data } = await verifyState(req, res)
  const tokenRes = await new WebClient()
    .oauth.v2.access({
      code: req.query.code,
      client_id: slackClientId,
      client_secret: slackClientSecret,
      redirect_uri: `https://${req.get('host')}${verifyPath}`,
    })

  const testRes = await new WebClient(tokenRes.access_token)
          .auth.test()

  // save user and team data to a database
  // maybe do something with the state `data`?

  const redirectURL = `slack://app?team=${team.id}&id=${team.appId}`
  const htmlResponse = '<html>' +
    `\n<meta http-equiv="refresh" content="0; URL=${redirectURL}">` +
    '\n<body>' +
    '\n  <h1>Success! Redirecting to the Slack App...</h1>' +
    `\n  <button onClick="window.location = '${redirectURL}'">Click here to redirect</button>` +
    `\n  <a href="${installPath}">Install again</a>`
  '\n</body></html>'
  res.writeHead(200, { 'Content-Type': 'text/html' })
  res.end(htmlResponse)
})

app.listen('3000')
```
