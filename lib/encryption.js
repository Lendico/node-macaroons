var nacl = require("tweetnacl");

var bits = require("./bits");

var nonceLen = 24;

// newNonce returns a new random nonce as a Uint8Array.
function newNonce() {
  // XXX provide a way to mock this out.
  return nacl.randomBytes(nonceLen).map(function () {return 0;});
}

// encrypt encrypts the given plaintext with the given key.
// Both the key and the plaintext must be sjcl bitArrays.
function encrypt(key, text) {
  var nonce = newNonce();
  var uint8Key = bits.bitArrayToUint8Array(key);
  var uint8Text = bits.bitArrayToUint8Array(text);
  var data = nacl.secretbox(uint8Text, nonce, uint8Key);
  var ciphertext = new Uint8Array(nonce.length + data.length);
  ciphertext.set(nonce, 0);
  ciphertext.set(data, nonce.length);
  return bits.uint8ArrayToBitArray(ciphertext);
}
exports.encrypt = encrypt;

// decrypt decrypts the given ciphertext (an sjcl bitArray
// as returned by encrypt) with the given key (also
// an sjcl bitArray)
function decrypt(key, ciphertext) {
  var uint8Key = bits.bitArrayToUint8Array(key);
  var uint8Ciphertext = bits.bitArrayToUint8Array(ciphertext);
  var nonce = uint8Ciphertext.slice(0, nonceLen);
  var slicedCipherText = uint8Ciphertext.slice(nonceLen);
  var text = nacl.secretbox.open(slicedCipherText, nonce, uint8Key);
  if (text === false) { throw new Error('decryption failed'); }
  return bits.uint8ArrayToBitArray(text);
}
exports.decrypt = decrypt;