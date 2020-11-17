# skynet-encryption-js
Public Key Authenticated Encryption. Method takes ED25519(encoded as base64) as input and converts it to Montgomery curve 25519 keys. Same keys are used for shared secret using ECDH, Encryption is done using xsalsa20-poly1305. Note: This is experimental project, user at your own risk.
