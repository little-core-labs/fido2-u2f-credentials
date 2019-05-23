const constants = require('./constants')

const HAS_CREDENTIALS_SUPPORT = false

module.exports = {
  constants,
  create,
  store,
  get,
}

async function create(opts) {
  assert(HAS_CREDENTIALS_SUPPORT, 'Credentials API is not supported.')
}

async function store(opts) {
  assert(HAS_CREDENTIALS_SUPPORT, 'Credentials API is not supported.')
}

async function get(opts) {
  assert(HAS_CREDENTIALS_SUPPORT, 'Credentials API is not supported.')
}
