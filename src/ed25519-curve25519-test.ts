import _sodium from 'libsodium-wrappers-sumo';
import { pki, pkcs5, md } from 'node-forge';
import randomBytes from "randombytes";
import nacl from 'tweetnacl';
import naclutil from 'tweetnacl-util';
export function toHexString(byteArray: Uint8Array): string {
  let s = "";
  // tslint:disable-next-line:only-arrow-functions
  byteArray.forEach(function (byte) {
    // tslint:disable-next-line:no-bitwise
    s += ("0" + (byte & 0xff).toString(16)).slice(-2);
  });
  return s;
}
function genKeyPairFromSeed(seed: string): { publicKey: Uint8Array; privateKey: Uint8Array } {
  // Get a 32-byte seed.
  seed = pkcs5.pbkdf2(seed, "", 1000, 32, md.sha256.create());
  const { publicKey, privateKey } = pki.ed25519.generateKeyPair({ seed });
  // return { publicKey: toHexString(publicKey), privateKey: toHexString(privateKey) };
  return { publicKey, privateKey };
}
function makeSeed(length: number): string {
  // Cryptographically-secure random number generator. It should use the
  // built-in crypto.getRandomValues in the browser.
  const array = randomBytes(length);
  return toHexString(array);
}
function genKeyPairAndSeed(length = 64): { publicKey: Uint8Array; privateKey: Uint8Array; seed: string } {
  const seed = makeSeed(length);
  return { ...genKeyPairFromSeed(seed), seed };
}
const convertEdToCurve = async (): Promise<void> => {
  try {
    await _sodium.ready;
    const sodium = _sodium;
    // BOB
    // tslint:disable-next-line:no-console
    console.log("########### BOB #############");
    const bob = genKeyPairAndSeed(32);
    // tslint:disable-next-line:no-console
    console.log("ED25519 : publicKey : " + toHexString(bob.publicKey));
    // tslint:disable-next-line:no-console
    console.log("ED25519 : publicKey : base64 : " + Buffer.from(bob.publicKey).toString('base64'));
    // tslint:disable-next-line:no-console
    console.log("ED25519 : privateKey : " + toHexString(bob.privateKey));
    // tslint:disable-next-line:no-console
    console.log("ED25519 : privateKey : base64 : " + Buffer.from(bob.privateKey).toString('base64'));
    // function buf2hex(buffer) { // buffer is an ArrayBuffer
    //   return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
    // }
    // tslint:disable-next-line:variable-name
    const bob_curve_pk = sodium.crypto_sign_ed25519_pk_to_curve25519(bob.publicKey);
    // tslint:disable-next-line:no-console
    console.log("X25519 : publicKey : " + toHexString(bob_curve_pk));
    // tslint:disable-next-line:no-console
    console.log("X25519 : publicKey : base64 : " + Buffer.from(bob_curve_pk).toString('base64'));
    // tslint:disable-next-line:variable-name
    const bob_curve_sk = sodium.crypto_sign_ed25519_sk_to_curve25519(bob.privateKey);
    // tslint:disable-next-line:no-console
    console.log("X25519 : privateKey : " + toHexString(bob_curve_sk));
    // tslint:disable-next-line:no-console
    console.log("X25519 : privateKey : base64 : " + Buffer.from(bob_curve_sk).toString('base64'));
    // ALICE
    // tslint:disable-next-line:no-console
    console.log("########### ALICE #############");
    const alice = genKeyPairAndSeed(32);
    // tslint:disable-next-line:no-console
    console.log("ED25519 : publicKey : " + toHexString(alice.publicKey));
    // tslint:disable-next-line:no-console
    console.log("ED25519 : publicKey : base64 : " + Buffer.from(alice.publicKey).toString('base64'));
    // tslint:disable-next-line:no-console
    console.log("ED25519 : privateKey : " + toHexString(alice.privateKey));
    // tslint:disable-next-line:no-console
    console.log("ED25519 : privateKey : base64 : " + Buffer.from(alice.privateKey).toString('base64'));
    // function buf2hex(buffer) { // buffer is an ArrayBuffer
    //   return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
    // }
    // tslint:disable-next-line:variable-name
    const alice_curve_pk = sodium.crypto_sign_ed25519_pk_to_curve25519(alice.publicKey);
    // tslint:disable-next-line:no-console
    console.log("X25519 : publicKey : " + toHexString(alice_curve_pk));
    // tslint:disable-next-line:no-console
    console.log("X25519 : publicKey : base64 : " + Buffer.from(alice_curve_pk).toString('base64'));
    // tslint:disable-next-line:variable-name
    const alice_curve_sk = sodium.crypto_sign_ed25519_sk_to_curve25519(alice.privateKey);
    // tslint:disable-next-line:no-console
    console.log("X25519 : privateKey : " + toHexString(alice_curve_sk));
    // tslint:disable-next-line:no-console
    console.log("X25519 : privateKey : base64 : " + Buffer.from(alice_curve_sk).toString('base64'));


    // tslint:disable-next-line:no-console
    console.log("########### STARTING ENCRYPTION #############");
    // generating key pairs
    // const bob = nacl.box.keyPair()
    // const alice = nacl.box.keyPair()
    // generating one time nonce for encryption
    const nonce = nacl.randomBytes(24)
    // message for Alice
    const utf8 = 'Hello Alice'
    // Bob encrypts message for Alice
    const box = nacl.box(
      naclutil.decodeUTF8(utf8),
      nonce,
      alice_curve_pk,
      bob_curve_sk
    )
    // somehow send this message to Alice
    const message = { box, nonce }
    // tslint:disable-next-line:no-console
    console.log("box: "+Buffer.from(message.box).toString('base64'));
    // tslint:disable-next-line:no-console
    console.log("nonce: "+Buffer.from(nonce).toString('base64'));

  }
  catch (e) {
    throw e;
  }
};
convertEdToCurve();


// ### Data Encryption for loggedIn user
// async function encryptData (privateKey: string, publicKey: string, data:string, nonce:string): Promise<string> {
//   try {
//     await _sodium.ready;
//     const sodium = _sodium;
//     const xPublicKey = sodium.crypto_sign_ed25519_pk_to_curve25519(Buffer.from(publicKey,"hex")); // Public key is of current logged in user(ephemeralPublicKey) OR Public key of another user.
//     const xPrivateKey = sodium.crypto_sign_ed25519_sk_to_curve25519(Buffer.from(privateKey,"hex")); // LoggedIn users Private Key
//      // tslint:disable-next-line:no-console
//      console.log("box: " +  xPublicKey);
//     // Bob encrypts message for Alice or Bobs encrypts his own file using ephemeral/drived publicKeys
//     const box = nacl.box(
//       naclutil.decodeUTF8(data),
//       Buffer.from(nonce),
//       xPublicKey,
//       xPrivateKey
//     )
//     // somehow send this message to Alice
//     const message = { box, nonce }
//     const cipherObject = {box : Buffer.from(message.box).toString('base64') , nonce: Buffer.from(nonce).toString('base64') };
//     // tslint:disable-next-line:no-console
//     console.log("box: " + cipherObject.box);
//     // tslint:disable-next-line:no-console
//     console.log("nonce: " + cipherObject.nonce);
//     // return Buffer.from(message).toString('base64');
//     return JSON.stringify(cipherObject);
//   }
//   catch (e) {
//     throw e;
//   }
// };
// ncryptData ("244a06a7dd2b145b6511fa0fed9126af5a7d9ab39c30a22857612a1d6d06f840","ce8fe6d1e9d258ae55abc5216a9e301341329d26b728acc500df07e6b5456902","Hello SkySpaces !!","EA2sKLJUhO7n6DhaKIr6BE7ojCTsMFON");
// encryptData ("JEoGp90rFFtlEfoP7ZEmr1p9mrOcMKIoV2EqHW0G+EA=","zo/m0enSWK5Vq8Uhap4wE0EynSa3KKzFAN8H5rVFaQI=","Hello SkySpaces !!","EA2sKLJUhO7n6DhaKIr6BE7ojCTsMFON");
