const attestation = require('./attestation')
const constants = require('./constants')
const defaults = require('./defaults')
const crypto = require('./crypto')
const assert = require('assert')
const extend = require('extend')
const debug = require('debug')('fido-u2f-credentials:assertion')
const asn1 = require('./asn1')
const cose = require('./cose')
const borc = require('borc')

const {
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
      'rpId',
      'timeout',
      'challenge',
      'extensions',
      'allowCredentials',
      'userVerification',
    ]
  }

  static get transports() {
    return [
      constants.USB_TRANSPORT,
      constants.NFC_TRANSPORT,
      constants.BLE_TRANSPORT,
    ]
  }

  static get defaults() {
    return defaults.assertion.request
  }

  constructor(opts) {
    opts = extend(true, Request.defaults, opts)

    if (undefined !== opts.rpId) {
      assert(isString(opts.rpId), 'rpId should be a string')
    }

    if (undefined !== opts.timeout) {
      assert(isNumber(opts.timeout), 'timeout must be number')
      assert(opts.timeout > 0, 'timeout must be greater than 0')
    }

    if (isString(opts.challenge)) {
      this.challenge = Buffer.from(opts.challenge, 'hex')
    } else if (isBuffer(opts.challenge)) {
      this.challenge = opts.challenge
    } else {
      this.challenge = opts.crypto.randomBytes(Request.CHALLENGE_BYTES)
    }

    assert(isArray(opts.allowCredentials),
      'allowCredentials must be an array')

    for (let i = 0 ; i < opts.allowCredentials.length; ++i) {
      const allowed = opts.allowCredentials[i]

      if (undefined === allowed.type) {
        allowed.type = constants.DEFAULT_CREDENTIAL_TYPE
      }

      if ('string' === typeof allowed.transports) {
        allowed.transports = [ allowed.transports ]
      }

      if (undefined !== allowed.transports) {
        assert(isArray(allowed.transports),
          `allowCredentials[${i}].transports should be an array`)
      }

      if (isArray(allowed.transports))
      for (let j = 0; j < allowed.transports.length; ++j){
        const transport = allowed.transports[j]
        assert(Request.transports.includes(transport),
          `Invalid transport at allowCredentials[${i}].transports[${j}]`)
      }
    }

    this.rpId = opts.rpId
    this.timeout = opts.timeout
    this.extensions = opts.extensions
    this.allowCredentials = opts.allowCredentials
    this.userVerification = opts.userVerification
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
    return defaults.assertion.response
  }

  constructor(request, credential, opts) {
    opts = extend(true, Response.defaults, opts)

    assert(isObject(credential), 'Expecting credential to be an object')

    assert(isObject(credential), 'Expecting credential to be an object')
    assert(constants.DEFAULT_CREDENTIAL_TYPE === credential.type,
      `Expecting credential.type to be '${constants.DEFAULT_CREDENTIAL_TYPE}'`)
    assert(isString(credential.id),
      'Expecting credential.id to be a string')

    assert(credential.rawId instanceof ArrayBuffer,
      'Expecting credential.rawId to be an ArrayBuffer')

    assert(isObject(credential.response),
      'Expecting credential.response to be an object')

    const { clientDataJSON } = credential.response

    this.credential = credential
    this.signature = Buffer.from(credential.response.signature)
    this.algorithm = undefined
    this.verified = false
    this.request = request
    this.data = JSON.parse(Buffer.from(clientDataJSON))
    this.auth = parseAssertionAuthData(Buffer.from(
      credential.response.authenticatorData))
    this.id = credential.id

    if (! (this.auth.flags & constants.FIDO_U2F_USER_PRESENTED)) {
      throw new Error('User not present during authentication')
    }

    for (const alg of attestation.Request.algorithms) {
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
        this.auth.rpIdHash,
        this.auth.flagsBuffer,
        this.auth.counterBuffer,
        hash
      ])

      for (const allowed of request.allowCredentials) {
        if (allowed.publicKey) {
          const publicKey = asn1.toPEM(allowed.publicKey)
          try {
            const verified = opts.crypto.verify(
              alg,
              this.signature,
              digest,
              publicKey
            )

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
  }
}

function parseAssertionAuthData(authData) {
  const rpIdHash = read(32)
  const flagsBuffer = read(1)
  const flags = flagsBuffer[0]
  const counterBuffer = read(4)
  const counter = counterBuffer.readUInt32BE(0)

  return {
    counterBuffer,
    flagsBuffer,
    rpIdHash,
    counter,
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
  Request,
  Response,
}
