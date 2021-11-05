const { runner, plan } = require('./test-plan')

module.exports = plan.then(runner.runTests)
