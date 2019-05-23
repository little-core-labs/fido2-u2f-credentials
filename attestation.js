const constants = require('./constants')
const defaults = require('./defaults')
const crypto = require('./crypto')
const assert = require('assert')
const extend = require('extend')
const debug = require('debug')('fido-u2f-credentials:attestation')
const asn1 = require('./asn1')
const cose = require('./cose')
const borc = require('borc')

const {
  isBoolean,
  isObject,
  isString,
  isBuffer,
  isNumber,
  isArray,
} = require('./util')

class Request {
  static get CHALLENGE_BYTES() {
    return 32
  }

  static get properties() {
    return [
      'rp',
      'user',
      'timeout',
      'challenge',
      'extensions',
      'attestation',
      'pubKeyCredParams',
      'excludeCredentials',
      'authenticatorSelection',
    ]
  }

  static get defaults() {
    return defaults.attestation.request
  }

  static get algorithms() {
    return [
      constants.ES256,
      constants.EdDSA,
      constants.ES384,
      constants.ES512,
      constants.PS256,
      constants.PS384,
      constants.PS512,
    ]
  }

  constructor(opts) {
    opts = extend(true, Request.defaults, opts)

    assert(isString(opts.attestation), 'attestation must be a string')

    assert(isObject(opts.rp), 'rp must be an object')
    assert(isString(opts.rp.id), 'rp.id must be a string')
    assert(isString(opts.rp.name), 'rp.name must be a string')

    if (opts.rp.icon) {
      assert(isString(opts.rp.icon), 'rp.icon must be a string')
    }

    assert(isObject(opts.user), 'user must be an object')
    assert(isBuffer(opts.user.id), 'user.id must be a buffer')
    assert(isString(opts.user.name), 'user.name must be a string')

    if (undefined === opts.user.displayName) {
      opts.user.displayName = opts.user.name
    }

    assert(isString(opts.user.displayName), 'user.displayName must be a string')

    if (opts.user.icon) {
      assert(isString(opts.user.icon), 'user.icon must be a string')
    }

    assert(isArray(opts.pubKeyCredParams), 'pubKeyCredParams must be an array')
    assert(opts.pubKeyCredParams.length, 'pubKeyCredParams cannot be empty')

    for (let i = 0 ;i < opts.pubKeyCredParams.length; ++i) {
      const params = opts.pubKeyCredParams[i]

      if (undefined === params.type) {
        params.type = constants.DEFAULT_CREDENTIAL_TYPE
      }

      assert(constants.DEFAULT_CREDENTIAL_TYPE === params.type,
        `pubKeyCredParams[${i}].type must be 'public-key'`)
    }

    if (undefined !== opts.excludeCredentials) {
      assert(isArray(opts.excludeCredentials),
        'excludeCredentials must be an array')

      for (let i = 0 ; i < opts.excludeCredentials; ++i) {
        const excluded = opts.excludeCredentials[i]

        if (undefined === excluded.type) {
          excluded.type = constants.DEFAULT_CREDENTIAL_TYPE
        }
      }
    }

    if (undefined !== opts.timeout) {
      assert(isNumber(opts.timeout), 'timeout must be number')
      assert(opts.timeout > 0, 'timeout must be greater than 0')
    }

    if (undefined !== opts.authenticatorSelection) {
      if (undefined !== opts.authenticatorSelection.authenticatorAttachment) {
        assert(isString(opts.authenticatorSelection.authenticatorAttachment),
          'authenticatorSelection.authenticatorAttachment should be a string')
      }

      if (undefined !== opts.authenticatorSelection.requireResidentKey) {
        assert(isBoolean(opts.authenticatorSelection.requireResidentKey),
          'authenticatorSelection.requireResidentKey should be a boolean')
      }

      if (undefined !== opts.authenticatorSelection.userVerification) {
        assert(isString(opts.authenticatorSelection.userVerification),
          'authenticatorSelection.userVerification should be a string')
      }
    }

    this.rp = opts.rp
    this.user = opts.user
    this.timeout = opts.timeout
    this.extensions = opts.extensions
    this.attestation = opts.attestation
    this.pubKeyCredParams = opts.pubKeyCredParams
    this.excludeCredentials = opts.excludeCredentials
    this.authenticatorSelection = opts.authenticatorSelection

    if (isString(opts.challenge)) {
      this.challenge = Buffer.from(opts.challenge, 'hex')
    } else if (isBuffer(opts.challenge)) {
      this.challenge = opts.challenge
    } else {
      this.challenge = opts.crypto.randomBytes(Request.CHALLENGE_BYTES)
    }
  }

  get publicKey() {
    const reduce = (publicKey, key) => undefined !== this[key]
      ? Object.assign(publicKey, { [key]: this[key]})
      : publicKey

    const publicKey = Request.properties.reduce(reduce, {})
    return publicKey
  }
}

class Response {
  static get defaults() {
    return defaults.attestation.response
  }

  constructor(request, credential, opts) {
    opts = extend(true, Response.defaults, opts)

    assert(isObject(credential), 'Expecting credential to be an object')
    assert(constants.DEFAULT_CREDENTIAL_TYPE === credential.type,
      `Expecting credential.type to be '${constants.DEFAULT_CREDENTIAL_TYPE}'`)
    assert(isString(credential.id),
      'Expecting credential.id to be a string')

    assert(credential.rawId instanceof ArrayBuffer,
      'Expecting credential.rawId to be an ArrayBuffer')

    assert(isObject(credential.response),
      'Expecting credential.response to be an object')

    this.request = request
    this.verified = false
    this.algorithm = undefined
    this.credential = credential
    this.attestationObject = borc.decodeFirst(
      Buffer.from(this.credential.response.attestationObject)
    )

    const { clientDataJSON } = credential.response
    const { fmt, attStmt } = this.attestationObject
    const algorithms = this.request.pubKeyCredParams.map(({ alg }) => alg)

    this.format = fmt
    this.auth = parseAttestationAuthData(this.attestationObject.authData)

    if (! (this.auth.flags & constants.FIDO_U2F_USER_PRESENTED)) {
      throw new Error('User not present during authentication')
    }

    if (fmt === constants.FIDO_U2F_FORMAT) {
      this.signature = attStmt.sig
      this.certificate = attStmt.x5c[0]
      this.certificatePEM = asn1.toPEM(this.certificate)
    } else {
      this.signature = null
      this.certificate = null
      this.certificatePEM = null
    }

    this.publicKey = cose.ecdhaToPkcs(this.auth.cosePublicKey)
    this.data = JSON.parse(Buffer.from(clientDataJSON))
    this.id = this.auth.credId

    this.publicKeyPEM = asn1.toPEM(this.publicKey)

    for (const alg of algorithms) {
      let hash = null

      try {
        hash = opts.crypto.hash(alg, Buffer.from(clientDataJSON))
      } catch (err) {
        debug(err)
      }

      if (!hash) {
        continue
      }

      const digest = Buffer.concat([
        Buffer.from([ constants.FIDO_U2F_RESERVED_BYTE ]),
        this.auth.rpIdHash,
        hash,
        this.auth.credId,
        this.publicKey
      ])

      try {
        const verified = opts.crypto.verify(
          alg,
          this.signature,
          digest,
          this.certificatePEM)

        if (verified) {
          this.algorithm = alg
          this.verified = true
          break
        }
      } catch (err) {
        debug(err)
      }
    }
  }
}

// borrowed from https://github.com/fido-alliance/webauthn-demo/blob/completed-demo/utils.js
function parseAttestationAuthData(authData) {
  const rpIdHash = read(32)
  const flagsBuffer = read(1)
  const flags = flagsBuffer[0]
  const counterBuffer = read(4)
  const counter = counterBuffer.readUInt32BE(0)
  const aaguid = read(16)
  const credIdLenBuffer = read(2)
  const credIdLen = credIdLenBuffer.readUInt16BE(0)
  const credId = read(credIdLen)
  const cosePublicKey = read.buffer.slice()

  return {
    cosePublicKey,
    counterBuffer,
    rpIdHash,
    flagsBuffer,
    counter,
    aaguid,
    credId,
    flags,
  }

  function read(size) {
    read.buffer = read.buffer || authData
    const buf = read.buffer.slice(0, size)
    read.buffer = read.buffer.slice(size)
    return buf
  }
}

module.exports = {
  Response,
  Request,
}
