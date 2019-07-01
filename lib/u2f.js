const { ES256 } = require('../constants')
const crypto = require('../crypto')
const assert = require('assert')
const b64 = require('base64url')

const {
  FIDO_U2F_AUTHENTICATION_TYPE,
  FIDO_U2F_REGISTATION_TYPE,
  FIDO_U2F_CHALLENGE_BYTES,
} = require('../constants')

function truncateBuffer(buffer, max) {
  return buffer.slice(0, max)
}

async function register(opts) {
  assert(null !== opts && 'object' === typeof opts,
    'Expecting options to be an object')

  const { userVerification = true } = opts

  assert(Buffer.isBuffer(opts.challenge), 'Expecting challenge to be a buffer')
  assert(opts.challenge.length >= FIDO_U2F_CHALLENGE_BYTES,
    `Expecting challenge to be at least ${FIDO_U2F_CHALLENGE_BYTES} bytes`)

  assert('boolean' === typeof userVerification,
    'Expecting userVerification to be a boolean')

  assert('string' === typeof opts.origin, 'Expecting origin to be a string')
  assert(opts.origin.length, 'origin cannot be empty')

  assert('string' === typeof opts.appId, 'Expecting appId to be a string')
  assert(opts.appId.length, 'appId cannot be empty')

  const maxChallengeBytes = FIDO_U2F_CHALLENGE_BYTES
  const { origin, appId } = opts
  const challenge = b64.encode(truncateBuffer(opts.challenge, maxChallengeBytes))
  const type = opts.type || FIDO_U2F_REGISTATION_TYPE

  console.log('CHALLENGE', challenge)
  const data = {
    challenge,
    origin,
    type
  }

  const clientDataJSON = JSON.stringify(data)
  const clientDataHash = crypto.hash(ES256, clientDataJSON)
  const appIdHash = appId ? crypto.hash('sha256', appId) : null

  return {
    clientDataJSON,
    clientDataHash,
    appIdHash,
  }
}

async function authenticate() {
}

module.exports = {
  authenticate,
  register,
}
