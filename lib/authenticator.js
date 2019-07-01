const util = require('util')

const $attestationObject = Symbol('attestationObject')
const $authenticatorData = Symbol('authenticatorData')
const $clientDataJSON = Symbol('clientDataJSON')
const $client = Symbol('client')

const toArrayBuffer = (value) => Uint8Array.from(Buffer.from(value)).buffer

class AuthenticatorClient {
  constructor(client) {
    this[$client] = client
  }

  get client() { return this[$client] }

  [util.inspect.custom]() {
    const { client } = this
    const wrap = new class AuthenticatorClient {}
    return Object.assign(wrap, { client })
  }

  async createCredential() {
  }

  async getAssertion() {
  }

  async isUserVerifyingPlatformAuthenticatorAvailable() {
  }
}

class AuthenticatorCoordinator {
}

class AuthenticatorResponse {
  constructor(clientDataJSON) {
    this[$clientDataJSON] = toArrayBuffer(clientDataJSON)
  }

  get clientDataJSON() { return this[$clientDataJSON] }

  [util.inspect.custom]() {
    const { clientDataJSON } = this
    const wrap = new class AuthenticatorResponse {}
    return Object.assign(wrap, { clientDataJSON })
  }
}

class AuthenticatorAssertionResponse extends AuthenticatorResponse {
  constructor(clientDataJSON, authenticatorData) {
    super(clientDataJSON)

    this[$authenticatorData] = toArrayBuffer(authenticatorData)
  }

  get authenticatorData() { return this[$authenticatorData] }

  [util.inspect.custom]() {
    const { authenticatorData } = this
    const wrap = new class AuthenticatorAttestationResponse {}
    return Object.assign(
      wrap,
      super[util.inspect.custom](),
      { authenticatorData })
  }
}

class AuthenticatorAttestationResponse extends AuthenticatorResponse {
  constructor(clientDataJSON, attestationObject) {
    super(clientDataJSON)

    this[$attestationObject] = toArrayBuffer(attestationObject)
  }

  get attestationObject() { return this[$attestationObject] }

  [util.inspect.custom]() {
    const { attestationObject } = this
    const wrap = new class AuthenticatorAttestationResponse {}
    return Object.assign(
      wrap,
      super[util.inspect.custom](),
      { attestationObject })
  }
}

module.exports = {
  AuthenticatorAttestationResponse,
  AuthenticatorAssertionResponse,
  AuthenticatorResponse,
}
