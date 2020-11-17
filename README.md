# skynet-encryption-js
ECIES - Public Key Authenticated Encryption 
It takes ED25519(encoded as base64) as input and converts it to Montgomery curve 25519 keys. 
X25519 keys are used for shared secret using ECDH.
Encryption is done using xsalsa20-poly1305 

Note: This is experimental project, user at your own risk.
