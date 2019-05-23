const { isFunction } = require('./util')
const attestation = require('./attestation')
const assertion = require('./assertion')
const constants = require('./constants')
const assert = require('assert')

const HAS_CREDENTIALS_SUPPORT = global.navigator && global.navigator.credentials

module.exports = {
  attestation,
  assertion,
  constants,
  create,
  get,
}

async function create(opts) {
  assert(HAS_CREDENTIALS_SUPPORT, 'Credentials API is not supported.')
  assert(isFunction(global.navigator.credentials.create),
    'navigator.credentials.create() API not supported')

  const request = new attestation.Request(opts)
  const credentials = await global.navigator.credentials.create(request)
  const response = new attestation.Response(request, credentials, opts)
  return response
}

async function get(opts) {
  assert(HAS_CREDENTIALS_SUPPORT, 'Credentials API is not supported.')
  assert(isFunction(global.navigator.credentials.get),
    'navigator.credentials.get() API not supported')

  const request = new assertion.Request(opts)
  const credentials = await global.navigator.credentials.get(request)
  const response = new assertion.Response(request, credentials, opts)
  return response
}
