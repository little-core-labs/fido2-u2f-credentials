const { randomBytes, createHash, createVerify } = require('crypto')
const constants = require('./constants')
const parseAsn1 = require('parse-asn1')
const elliptic = require('elliptic')

function hash(alg, buffer) {
  const hashType = constantToHash(alg)

  if (!hashType) {
    return null
  }

  return createHash(hashType).update(Buffer.from(buffer)).digest()
}

function verify(alg, signature, data, publicKey) {
  const verifierType = constantToVerifier(alg)
  const curveType = constantToCurve(alg)

  if (!verifierType) {
    throw new TypeError(`Invalid verification algorithm: ${alg}`)
  }

  const verifier = createVerify(verifierType)
  const cert = parseAsn1(publicKey)

  verifier.update(data).end()

  if (curveType) {
    const curve = elliptic.ec(curveType)
    const digest = verifier._hash.digest()
    return curve.verify(
      digest,
      signature,
      cert.data.subjectPublicKey.data
    )
  } else {
    return verifier.verifier(publicKey, Buffer.from(signature))
  }
}

function constantToHash(alg) {
  return constantToVerifier(alg)
}

function constantToCurve(alg) {
  switch (alg) {
    case constants.EdDSA: return 'ed25519'
    case constants.ES256: return 'p256'
    case constants.ES384: return 'p384'
    case constants.ES512: return 'p521'
    default: return null
  }
}

function constantToVerifier(alg) {
  switch (alg) {
    case constants.ES256: return 'sha256'
    case constants.ES384: return 'sha384'
    case constants.ES512: return 'sha512'
    case constants.PS256: return 'rsa-sha256'
    case constants.PS384: return 'rsa-sha384'
    case constants.PS512: return 'rsa-sha512'
    default: return null
  }
}

module.exports = {
  randomBytes,
  verify,
  hash,
}
