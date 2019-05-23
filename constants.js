const FIDO_U2F_USER_PRESENTED = 0x01
const FIDO_U2F_RESERVED_BYTE = 0x00
const FIDO_U2F_FORMAT = 'fido-u2f'

const ASN1_PUBLIC_KEY_HEADER_HEX = '3059301306072a8648ce3d020106082a8648ce3d030107034200'
const ASN1_OCTET_STRING_BYTE = 0x04

// https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
const COSE_KEY_X_COORDINATE = -2
const COSE_KEY_Y_COORDINATE = -3

const DEFAULT_AUTHENTICATOR_ATTACHMENT = 'cross-platform'
const DEFAULT_USER_VERIFICATION = 'preferred'
const DEFAULT_CREDENTIAL_TYPE = 'public-key'
const DEFAULT_ATTESTATION = 'indirect'

// credential transports
const USB_TRANSPORT = 'usb'
const NFC_TRANSPORT = 'nfc'
const BLE_TRANSPORT = 'ble'

// this is the default and likely always what will be used
const ES256 = -7 // SHA-256

// these are here for completeness
const EdDSA = -8 // EdDSA
const ES384 = -35 // SHA-384
const ES512 = -36 // SHA-512
const PS256 = -37 // RSASSA-PSS w/ SHA-256
const PS384 = -38 // RSASSA-PSS w/ SHA-384
const PS512 = -39 // RSASSA-PSS w/ SHA-512

module.exports = Object.freeze(Object.seal({
  DEFAULT_AUTHENTICATOR_ATTACHMENT,
  DEFAULT_USER_VERIFICATION,
  DEFAULT_CREDENTIAL_TYPE,
  DEFAULT_ATTESTATION,

  ASN1_PUBLIC_KEY_HEADER_HEX,
  ASN1_OCTET_STRING_BYTE,

  COSE_KEY_X_COORDINATE,
  COSE_KEY_Y_COORDINATE,

  FIDO_U2F_USER_PRESENTED,
  FIDO_U2F_RESERVED_BYTE,
  FIDO_U2F_FORMAT,

  USB_TRANSPORT,
  NFC_TRANSPORT,
  BLE_TRANSPORT,

  ES256,

  EdDSA,
  ES384,
  ES512,

  PS256,
  PS384,
  PS512,
}))
