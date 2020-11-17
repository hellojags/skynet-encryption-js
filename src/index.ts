import _sodium from 'libsodium-wrappers-sumo';
import nacl from 'tweetnacl';
import naclutil from 'tweetnacl-util';

// Inputes are Base64Encoded. 
// ### Data Encryption for loggedIn user
export async function encryptData (privateKey: string, publicKey: string, data:string, nonce:string): Promise<string> {
  try {
    // tslint:disable-next-line:no-console
    console.log("#####  Encryption ######");
    // Question (Sia Team): Shall I derive new KeyPair from master seed per file? like shown beloow
    // const ephemeralKeys = deriveChildSeed(session.skydbseed, nonce);
    // use ephemeral keys per file to encrypt and decrypt
    await _sodium.ready;
    const sodium = _sodium;
    const xPublicKey = sodium.crypto_sign_ed25519_pk_to_curve25519(naclutil.decodeBase64(publicKey)); // Public key is of current logged in user(ephemeralPublicKey) OR Public key of another user.
    const xPrivateKey = sodium.crypto_sign_ed25519_sk_to_curve25519(naclutil.decodeBase64(privateKey)); // LoggedIn users Private Key
    // Bob encrypts message for Alice or Bobs encrypts his own file using ephemeral/drived publicKeys
    const box = nacl.box(
      naclutil.decodeUTF8(data),
      naclutil.decodeBase64(nonce),
      xPublicKey,
      xPrivateKey
    )
    const cipherObject = {version:"v1", ciphertext : naclutil.encodeBase64(box), publicKey, nonce };
    // tslint:disable-next-line:no-console
    console.log("cipherObject"+JSON.stringify(cipherObject));
    return JSON.stringify(cipherObject);
  }
  catch (e) {
    throw e;
  }
};
export const decryptData = async (privateKey: string, publicKey: string, data:string): Promise<string> => {
  try {
     // tslint:disable-next-line:no-console
     console.log("#####  Decryption ######");
    await _sodium.ready;
    const sodium = _sodium;
    const cipherObj = JSON.parse(data);
    const box = naclutil.decodeBase64(cipherObj.ciphertext);
    const nonce = naclutil.decodeBase64(cipherObj.nonce);
    const xPrivateKey = sodium.crypto_sign_ed25519_sk_to_curve25519(naclutil.decodeBase64(privateKey)); // LoggedIn users Private Key
    const xPublicKey = sodium.crypto_sign_ed25519_pk_to_curve25519(naclutil.decodeBase64(publicKey)); // Public key is of current logged in user(ephemeralPublicKey) OR Public key of another user.
    // Alice decrypts message from Bob(using her PubKey) or Alice decrypts his own file using ephemeral/drived privatekey
    const payload = nacl.box.open(box,nonce,xPublicKey,xPrivateKey);
    const plainTextMessage = payload ? naclutil.encodeUTF8(payload) : "";
    // tslint:disable-next-line:no-console
    console.log("Decrypted: " + plainTextMessage);
    return plainTextMessage;
  }
  catch (e) {
    throw e;
  }
};

// First run Encrypt method and then uncomment and run decrypt method.
// encryptData ("P4UPEMoG1qWOfe3soMQRoQPyRZvIuL/95ByWpYBUQIa8m3WMFN3PdUgFb3PIguSV1dJPD9tamqCLX76Ag9t2Gw==","gvvJpIAE27HKX40s520U8atHAx1cErQp2B/uRe2wmBo=","Hello SkySpaces !!","ldB22oYZh/HP46XVJCRh/J6qOsbV/v7s");
 decryptData ("e8v2WhHuXaz2JhLhlt4ny+I0xEgKxdCzXsjQ2oZRgleC+8mkgATbscpfjSznbRTxq0cDHVwStCnYH+5F7bCYGg==","vJt1jBTdz3VIBW9zyILkldXSTw/bWpqgi1++gIPbdhs=","{\"version\":\"v1\",\"ciphertext\":\"YYFFrfY0xd6PqPNzrx5soLOtXsmkPviEzoh0ine4h6+oMQ==\",\"nonce\":\"ldB22oYZh/HP46XVJCRh/J6qOsbV/v7s\"}");