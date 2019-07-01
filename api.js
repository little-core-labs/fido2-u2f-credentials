const { isFunction } = require('./util')
const attestation = require('./attestation')
const assertion = require('./assertion')
const constants = require('./constants')
const assert = require('assert')

// factory
module.exports = (binding) => new API(binding)

class API {
  constructor(binding) {
    this.binding = binding
    this.attestation = attestation
    this.assertion =  assertion
    this.constants =  constants
  }

  isSupported() {
    return null !== this.binding
      && 'object' === typeof this.binding
      && 'function' === typeof this.binding.create
      && 'function' === typeof this.binding.get
  }

  async create(opts) {
    assert(this.isSupported(), 'Credentials API is not supported.')

    const request = new attestation.Request(opts)
    const credential = await this.binding.create(request)
    const response = new attestation.Response(request, credential, opts)
    return response
  }

  async get(opts) {
    assert(this.isSupported(), 'Credentials API is not supported.')

    const request = new assertion.Request(opts)
    const credential = await this.binding.get(request)
    const response = new assertion.Response(request, credential, opts)
    return response
  }
}
