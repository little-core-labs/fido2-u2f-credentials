const constants = require('./constants')
const crypto = require('./crypto')

exports.assertion = {
  request: {
    crypto,
    userVerification: constants.DEFAULT_USER_VERIFICATION,
  },

  response: {
    crypto,
  }
}

exports.attestation = {
  request: {
    crypto,
    attestation: constants.DEFAULT_ATTESTATION,
    authenticatorSelection: {
      authenticatorAttachment: constants.DEFAULT_AUTHENTICATOR_ATTACHMENT,
      requireResidentKey: false,
      userVerification: constants.DEFAULT_USER_VERIFICATION,
    },
  },

  response: {
    crypto,
  }
}
