const { PUBLIC_KEY_CREDENTIAL_TYPE } = require('../constants')
const assert = require('assert')
const util = require('util')
const b64 = require('base64url')

const PUBLIC_KEY_TYPE = 'public-key'

const $id = Symbol('id')
const $type = Symbol('type')
const $rawId = Symbol('rawId')
const $response = Symbol('response')
const $extenstions = Symbol('extenstions')

// derived from https://github.com/WebKit/webkit/blob/master/Source/WebCore/Modules/credentialmanagement/BasicCredential.h
class BaseCredential {
  static get PUBLIC_KEY() { return PUBLIC_KEY_TYPE }

  constructor(id, type) {
    this[$id] = b64.encode(Buffer.from(id))
    this[$type] = type
  }

  get id() { return this[$id] || null }
  get type() { return this[$type] || null }

  [util.inspect.custom]() {
    const { id, type } = this
    const wrap = new class BaseCredential {}
    return Object.assign(wrap, { id, type })
  }
}

// derived from https://github.com/WebKit/webkit/blob/master/Source/WebCore/Modules/webauthn/PublicKeyCredential.h
class PublicKeyCredential extends BaseCredential {
  constructor(id, response, extenstions) {
    super(Buffer.from(id).toString('base64'), PUBLIC_KEY_TYPE)

    this[$type] = PUBLIC_KEY_TYPE
    this[$rawId] = Uint8Array.from(Buffer.from(id)).buffer
    this[$response] = response
    this[$extenstions] = extenstions
  }

  get rawId() { return this[$rawId] || null}
  get response() { return this[$response] || null }

  [util.inspect.custom]() {
    const { rawId, response } = this
    const wrap = new class PublicKeyCredential {}
    return Object.assign(
      wrap,
      super[util.inspect.custom](),
      { rawId, response })
  }

  getClientExtensions() {
    return this[$extenstions]
  }

  async isUserVerifyingPlatformAuthenticatorAvailable() {
    assert(false, new Error('Not Implemented'))
  }
}

module.exports = {
  PublicKeyCredential,
  BaseCredential,
}
