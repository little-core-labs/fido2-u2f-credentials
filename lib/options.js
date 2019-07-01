const { PUBLIC_KEY_CREDENTIAL_TYPE } = require('../constants')
const { WEBAUTHN_REGISTATION_TYPE } = require('../constants')
const { inspect } = require('./inspect')
const { toJSON } = require('./json')
const assert = require('assert')
const util = require('util')

const $rp = Symbol('rp')
const $alg = Symbol('alg')
const $user = Symbol('user')
const $timeout = Symbol('timeout')
const $challenge = Symbol('challenge')
const $extensions = Symbol('extensions')
const $attestation = Symbol('attestation')
const $pubKeyCredParams = Symbol('pubKeyCredParams')
const $excludeCredentials = Symbol('excludeCredentials')
const $authenticatorSelection = Symbol('authenticatorSelection')

class BaseOptions {
  constructor(opts) {
    assert(opts && 'object' === typeof opts, 'Expecting options to be an object')

    const { prototype } = this.constructor
    Object.defineProperties(this, Object.getOwnPropertyDescriptors(prototype))
  }
}

// derived from: https://github.com/WebKit/webkit/blob/master/Source/WebCore/Modules/webauthn/PublicKeyCredentialCreationOptions.h
class PublicKeyCredentialCreationOptions extends BaseOptions {
  constructor(opts) {
    super(opts)

    const { prototype } = this.constructor

    for (const key in opts) {
      assert(key in prototype, `Invalid property ${key} in creation options`)

      this[key] = opts[key]
    }

    if (this.pubKeyCredParams) {
      this.pubKeyCredParams = this.pubKeyCredParams.map((params) => {
        return new PublicKeyCredentialCreationOptionsParameters(params)
      })
    }
  }

  get rp() { return this[$rp] }
  set rp(rp) {
    this[$rp] = rp
  }

  get user() { return this[$user] }
  set user(user) {
    this[$user] = user
  }

  get timeout() { return this[$timeout] }
  set timeout(timeout) {
    this[$timeout] = timeout
  }

  get challenge() { return this[$challenge] }
  set challenge(challenge) {
    this[$challenge] = challenge
  }

  get extensions() { return this[$extensions] }
  set extensions(extensions) {
    this[$extensions] = extensions
  }

  get attestation() { return this[$attestation] }
  set attestation(attestation) {
    this[$attestation] = attestation
  }

  get pubKeyCredParams() { return this[$pubKeyCredParams] }
  set pubKeyCredParams(pubKeyCredParams) {
    this[$pubKeyCredParams] = pubKeyCredParams
  }

  get excludeCredentials() { return this[$excludeCredentials] }
  set excludeCredentials(excludeCredentials) {
    this[$excludeCredentials] = excludeCredentials
  }

  get authenticatorSelection() { return this[$authenticatorSelection] }
  set authenticatorSelection(authenticatorSelection) {
    this[$authenticatorSelection] = authenticatorSelection
  }

  [util.inspect.custom]() {
    const holder = new class PublicKeyCredentialCreationOptions {}
    return inspect(holder, this)
  }

  toJSON() {
    return toJSON(this)
  }
}

class PublicKeyCredentialCreationOptionsParameters extends BaseOptions {
  constructor(opts) {
    super(opts)

    this.alg = opts.alg
  }

  get type() { return PUBLIC_KEY_CREDENTIAL_TYPE }
  get alg() { return this[$alg] }
  set alg(alg) {
    this[$alg] = alg
  }

  [util.inspect.custom]() {
    const holder = new class PublicKeyCredentialCreationOptionsParameters {}
    return inspect(holder, this)
  }

  toJSON() {
    return toJSON(this)
  }

  encode() {
  }

  decode() {
  }
}

Object.defineProperties(PublicKeyCredentialCreationOptions.prototype, {
  [$rp]: { enumerable: false, writable: true, },
  [$user]: { enumerable: false, writable: true, },
  [$timeout]: { enumerable: false, writable: true, },
  [$challenge]: { enumerable: false, writable: true, },
  [$extensions]: { enumerable: false, writable: true, },
  [$attestation]: { enumerable: false, writable: true, },
  [$pubKeyCredParams]: { enumerable: false, writable: true, },
  [$excludeCredentials]: { enumerable: false, writable: true, },
  [$authenticatorSelection]: { enumerable: false, writable: true, },

  rp: { enumerable: true },
  user: { enumerable: true },
  timeout: { enumerable: true },
  challenge: { enumerable: true },
  extensions: { enumerable: true },
  attestation: { enumerable: true },
  pubKeyCredParams: { enumerable: true },
  excludeCredentials: { enumerable: true },
  authenticatorSelection: { enumerable: true },
})

Object.defineProperties(PublicKeyCredentialCreationOptionsParameters.prototype, {
  [$alg]: { enumerable: false, writable: true, },
  alg: { enumerable: true },
})

Object.seal(PublicKeyCredentialCreationOptions.prototype)
Object.seal(PublicKeyCredentialCreationOptionsParameters.prototype)

module.exports = {
  PublicKeyCredentialCreationOptions
}
