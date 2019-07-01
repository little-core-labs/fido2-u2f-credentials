const { PublicKeyCredentialCreationOptions } = require('./options')
const { AuthenticatorAttestationResponse } = require('./authenticator')
const { parseAttestationAuthData } = require('../attestation')
const { PublicKeyCredential } = require('./credential')
const assert = require('assert')
const tder = require('tder')
const borc = require('borc')
const hid = require('./hid')
const u2f = require('./u2f')

const {
  DISCOURAGED_USER_VERIFICATION,
  PREFERRED_USER_VERIFICATION,
  REQUIRED_USER_VERIFICATION,
  COSE_KEY_X_COORDINATE,
  COSE_KEY_Y_COORDINATE,
  FIDO_U2F_FORMAT,
} = require('../constants')

const positiveUserVerificationTypes = [
  PREFERRED_USER_VERIFICATION,
  REQUIRED_USER_VERIFICATION,
  true,
]

const negativeUserVerificationTypes = [
  DISCOURAGED_USER_VERIFICATION,
  false,
]

const U2F_COMMAND_REGISTER = 0x01
const U2F_COMMAND_AUTHENTICATE = 0x02
const U2F_COMMAND_VERSION = 0x03

const NOT_SATISIFED_BUFFER = Buffer.from([ 0x69, 0x85 ])

const sleep = async (ms) => new Promise((done) => setTimeout(done, ms))

function parseUserVerification(opts) {
  const { userVerification } = opts.authenticatorSelection
  if (positiveUserVerificationTypes.includes(userVerification)) {
    return true
  } else if (negativeUserVerificationTypes.includes(userVerification)) {
    return false
  } else {
    assert(undefined === userVerification,
      `Invalid userVerification value: ${userVerification}`)
  }
}

async function create(request) {
  assert(null !== request, 'Request object cannot be null')
  assert('object' === typeof request, 'Expecting request to be an object')
  assert('publicKey' in request, 'Missing publicKey object in request')

  let discoveryRetries = 16
  let devices = null

  do {
    devices = await hid.discover()
    await sleep(1000)
  } while (null === devices || 0 === devices.length && discoveryRetries-- > 0)

  assert(devices && devices.length > 0, 'Unable to discover devices')
  const options = new PublicKeyCredentialCreationOptions(request.publicKey)

  const userVerification = parseUserVerification(options)
  const client  = await u2f.register({
    challenge: options.challenge,
    userVerification,
    origin: options.rp.name,
    appId: options.rp.id,
  })

  const { clientDataHash, clientDataJSON, appIdHash } = client
  const message = Buffer.concat([ clientDataHash, appIdHash ])

  let retries = 16
  let error = null
  let res = null
  let len = 0

  do {
    if (retries-- <= 0) {
      break
    }

    for (const device of devices) {
      //const p1 = 0
      const p1 = userVerification ? 3 : 0

      try {
        res = await hid.send(device, U2F_COMMAND_REGISTER, p1, message)
        len = res.init.bcnth << 8 | res.init.bcntl

        if (2 != len) {
          break
        }
      } catch (err) {
        error = err
      }
    }

    if (!res || !res.data || 2 === res.data.length) {
      await sleep(200)
    }
  } while (
    res &&
    2 === len &&
    devices.length &&
    userVerification &&
    0 === Buffer.compare(
      res.init.data.slice(0, 2),
      NOT_SATISIFED_BUFFER))

  if (null !== error) {
    throw error
  }

  // below is some of the ugliest code I have ever put down on paper
  // following https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-client-to-authenticator-protocol-v2.0-rd-20180702.html#u2f-authenticatorMakeCredential-interoperability
  const data = res.body
  const reservedByte = data.readUInt8(0)
  const userPublicKey = data.slice(1, 66)
  const keyLengthHandleByte = data.readUInt8(66)
  const keyHandle = data.slice(67).slice(0, keyLengthHandleByte)
  const certificateInfo = tder.parse(data.slice(67 + keyLengthHandleByte))
  const certificate = data.slice(67 + keyLengthHandleByte).slice(0, certificateInfo.dataLength + certificateInfo.headerLength)
  const signature = data.slice(67).slice(keyLengthHandleByte).slice(certificate.length)
  //certificate.length)

  console.log('certlen', certificate.length);
  const coseEncodedCredentialPublicKey = Buffer.alloc(77)
  const credentialIdLength = Buffer.alloc(2)

  const map = new Map()
  map.set(1, 2)
  map.set(3, options.pubKeyCredParams[0].alg)
  map.set(-1, 1)
  map.set(COSE_KEY_X_COORDINATE, userPublicKey.slice(1).slice(0, 32))
  map.set(COSE_KEY_Y_COORDINATE, userPublicKey.slice(1).slice(32))

  const coseData = borc.encode(map)

  coseData.copy(coseEncodedCredentialPublicKey)
  credentialIdLength.writeUInt16BE(keyLengthHandleByte)

  const attestedCredData = Buffer.concat([
    Buffer.alloc(16),
    credentialIdLength,
    keyHandle,
    coseEncodedCredentialPublicKey
  ])

  console.log('appIdHash', appIdHash);
  const flags = Buffer.from([ 0x41 ]) // 0x41 = 0b01000001 = 65
  const authenticatorData = Buffer.concat([
    appIdHash,
    flags,
    Buffer.alloc(4),
    attestedCredData
  ])

  console.log(authenticatorData.length, authenticatorData.toString('hex'));
  assert(0x05 === reservedByte,
    'Invalided reserved byte in response registeration data')

  const attestationObject = borc.encode(new Map(Object.entries({
    fmt: FIDO_U2F_FORMAT,
    authData: authenticatorData,
    attStmt: {
      sig: signature,
      x5c: [ certificate ]
    }
  })))

  const response = new AuthenticatorAttestationResponse(
    clientDataJSON,
    attestationObject)

  const credential = new PublicKeyCredential(keyHandle, response)
  return credential
}
async function get(request) {
}

module.exports = {
  create,
  get,
}
