const constants = require('./constants')

const ASN1_PUBLIC_KEY_HEADER = Buffer.from(
  constants.ASN1_PUBLIC_KEY_HEADER_HEX,
  'hex'
)

/**
 * If (buffer.length == 65 && buffer[0] == 0x04), then
 * encode rawpublic key to ASN structure, adding metadata:
 *
 *  SEQUENCE {
 *    SEQUENCE {
 *      OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
 *      OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
 *    }
 *    BITSTRING <raw public key>
 * }
 *
 * Luckily, to do that, we just need to prefix it with constant
 * 26 bytes (metadata is constant).
 * borrowed from: https://github.com/fido-alliance/webauthn-demo/blob/completed-demo/utils.js#L139
 * see also: http://luca.ntop.org/Teaching/Appunti/asn1.html
 */

function toPEM(buffer) {
	let pem = ''
	let type

	if (buffer.length == 65 && buffer[0] == constants.ASN1_OCTET_STRING_BYTE) {
		type = 'PUBLIC KEY'
		buffer = Buffer.concat([ ASN1_PUBLIC_KEY_HEADER, buffer ])
	} else {
		type = 'CERTIFICATE'
	}

	const b64cert = buffer.toString('base64')

	for (let i = 0; i < Math.ceil(b64cert.length / 64); i++) {
		pem += b64cert.substr(i * 64, 64) + '\n'
	}

	pem = `-----BEGIN ${type}-----\n` + pem + `-----END ${type}-----\n`

	return pem
}

module.exports = {
  toPEM
}
