const credentials = require('./')

if ('window' in global) {
  global.b64 = require('base64url')
  global.bytes = Buffer.from('bc651753973ea10b5b7a773adb32de7087e9721099a8db056a4afe3a0f0d7034', 'hex')
}

const rp = {
  id: 'window' in global ? window.location.hostname : 'localhost',
  name: 'window' in global ? window.location.hostname : 'http://localhost:3000',
}

const challenge = Buffer.from('bc651753973ea10b5b7a773adb32de7087e9721099a8db056a4afe3a0f0d7034', 'hex')
//const challenge = null
const user = {
  id: Buffer.from('alice@bob.com'),
  name: 'alice@bob.com',
  displayName: 'Alice'
}

const pubKeyCredParams = [{
  type: 'public-key',
  alg: credentials.constants.ES256
}]

void async function main() {
  const response = await credentials.create({ rp, user, challenge, pubKeyCredParams })

  if ('undefined' !== typeof window) {
    console.log('create', response);
  }

  console.log('id', response.id.toString('hex'));
  console.log('verified', response.verified);
  const res = await credentials.get({
    allowCredentials: [{
      id: response.id,
      // providing the raw public key buffer
      // allows for client side verification
      publicKey: response.publicKey
    }]
  })

  if ('undefined' !== typeof window) {
    console.log('get', res);
  }
}().catch(console.error)
