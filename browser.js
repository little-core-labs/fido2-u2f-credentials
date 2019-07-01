const api = require('./api')

module.exports = api(global.navigator && global.navigator.credentials)
