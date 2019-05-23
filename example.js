const credentials = require('./')

void async function main() {
  const response = await credentials.create({
    rp: {
      id: window.location.hostname,
      name: window.location.hostname,
    },

    user: {
      id: Buffer.from('alice@bob.com'),
      name: 'alice@bob.com',
      displayName: 'Alice'
    },

    pubKeyCredParams: [{
      type: 'public-key',
      alg: credentials.constants.ES256
    }]
  })

  const res = await credentials.get({
    allowCredentials: [{
      id: response.id,
      // providing the raw public key buffer
      // allows for client side verification
      publicKey: response.publicKey
    }]
  })

  console.log('get', res);
  console.log('create', response);
}().catch(console.error)
