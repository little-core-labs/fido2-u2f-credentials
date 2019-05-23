const constants = require('./constants')
const borc = require('borc')

/**
 * +------+-------+-------+---------+----------------------------------+
 * | name | key   | label | type    | description                      |
 * |      | type  |       |         |                                  |
 * +------+-------+-------+---------+----------------------------------+
 * | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
 * |      |       |       | tstr    | the COSE Curves registry         |
 * |      |       |       |         |                                  |
 * | x    | 2     | -2    | bstr    | X Coordinate                     |
 * |      |       |       |         |                                  |
 * | y    | 2     | -3    | bstr /  | Y Coordinate                     |
 * |      |       |       | bool    |                                  |
 * |      |       |       |         |                                  |
 * | d    | 2     | -4    | bstr    | Private key                      |
 * +------+-------+-------+---------+----------------------------------+
 */
function ecdhaToPkcs(cosePublicKey) {
  const coseData = borc.decodeFirst(cosePublicKey)
  const tag = Buffer.from([ constants.ASN1_OCTET_STRING_BYTE ])
  const x = coseData.get(constants.COSE_KEY_X_COORDINATE)
  const y = coseData.get(constants.COSE_KEY_Y_COORDINATE)
  return Buffer.concat([tag, x, y])
}

module.exports = {
  ecdhaToPkcs
}
