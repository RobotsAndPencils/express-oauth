const cookie = require('cookie')
const supposed = require('supposed')
const expect = require('unexpected')
const pkg = require('./package.json')
const { ExpressOAuth } = require('.')

const suite = supposed.Suite({
  name: pkg.name,
  assertionLibrary: expect,
  inject: { ExpressOAuth, cookie },
})

const runner = suite.runner({
  cwd: __dirname,
})

const plan = runner.plan()

module.exports = { suite, runner, plan }
