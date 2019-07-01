fido2-u2f-credentials
====================

**WIP** Create and and get FIDO U2F credentials

## Installation

```sh
$ npm install fido2-u2f-credentials
```

## Usage

```js
const credentials = require('fido2-u2f-credentials')
const attestationResponse = await credentials.create({
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
```

```js
const credentials = require('fido2-u2f-credentials')
const assertionResponse = await credentials.get({
  allowCredentials: [{
    id: response.id,
    // providing the raw public key buffer
    // allows for client side verification
    publicKey: response.publicKey
  }]
})
```

## TODO

* Tests
* Implement WebAuthn credentials interface using
  [hid](https://github.com/hyperdivision/hid)

## API

### `creds = credentials.create(opts)`

Creates a new FIDO U2F credential attestation where `opts` is everything
defined for the [`PublicKeyCredentialCreationOptions` interface](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions)

and `opts.crypto` is an optional object containing

```js
{
  // hash buffer based on COSE algorithm type
  hash(algorithm, buffer),
  // verify data with signature and public key based on COSE algorithm type
  verify(algorithm, signature, data, publicKey)
}
```

### `creds = credentials.get(opts)`

Creates a new FIDO U2F credential assertion where `opts` is everything
defined for the
[`PublicKeyCredentialRequestOptions` interface](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions)

and `opts.crypto` is an optional object containing

```js
{
  // hash buffer based on COSE algorithm type
  hash(algorithm, buffer),
  // verify data with signature and public key based on COSE algorithm type
  verify(algorithm, signature, data, publicKey)
}
```

### `credentials.attestation.Request`

The internal attestation request class passed to
`navigator.credentials.create(request)`.

### `credentials.attestation.Response`

The attestation response class that wraps the
`PublicKeyCredential` returned from `navigator.credentials.create(request)`.

#### `response.request`

A pointer back to the `credentials.attestation.Request` object that
initiated the request.

#### `response.verified`

A `boolean` that indicates the response verified the signature from the
attestation.

#### `response.algorithm`

The COSE algorithm type constant.

#### `response.credential`

The `PublicKeyCredential` returned from `navigator.credentials.create()`.

#### `response.attestationObject`

The decoded CBOR attestation object from the response
`PublicKeyCredential`.

#### `response.signature`

The attestation response signature buffer. If the attestation is
`'none'` then this will be `null`.

#### `response.certificate`

The attestation response certificate buffer. If the attestation is
`'none'` then this will be `null`.

#### `response.certificatePEM`

The attestation response certificate in PEM format. If the attestation is
`'none'` then this will be `null`.

#### `response.format`

The attestation response format.

#### `response.auth`

The parsed attestation authentication data from the
`PublicKeyCredential` response.

#### `response.publicKey`

The PKCS representation of the COSE public key in the `PublicKeyCredential`
response. This should be saved somewhere should you need assertions to be
verified on the client or off device.

#### `response.data`

The parsed `clientDataJSON` from the `PublicKeyCredential` response.

#### `response.id`

The credential ID. This must be saved somewhere to reference the
`PublicKeyCredential` on the device.

### `credentials.assertion.Request`

The internal assertion request class passed to
`navigator.credentials.get(request)`.

### `credentials.assertion.Response`

The assertion response class that wraps the
`PublicKeyCredential` returned from `navigator.credentials.get(request)`.

#### `response.credential`

The `PublicKeyCredential` returned from `navigator.credentials.get()`.

#### `response.data`

The parsed `clientDataJSON` from the `PublicKeyCredential` response.

#### `response.id`

The credential ID. This must be saved somewhere to reference the
`PublicKeyCredential` on the device.

#### `response.signature`

The assertion response signature buffer.

#### `response.request`

A pointer back to the `credentials.assertion.Request` object that
initiated the request.

#### `response.verified`

A `boolean` that indicates the response verified the signature from the
assertion on the client.

#### `response.algorithm`

The COSE algorithm type constant.

#### `response.auth`

The parsed assertion authentication data from the
`PublicKeyCredential` response.

## License

MIT
