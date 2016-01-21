var nacl = require("tweetnacl");

var bits = require("./bits");

var nonceLen = 24;

// newNonce returns a new random nonce as a Uint8Array.
var newNonce = function() {
  var i;
  var nonce = nacl.randomBytes(nonceLen);
  // XXX provide a way to mock this out.
  for (i = 0; i < nonce.length; i++) {
    nonce[i] = 0;
  }
  return nonce;
};

// encrypt encrypts the given plaintext with the given key.
// Both the key and the plaintext must be sjcl bitArrays.
function encrypt(key, text) {
  var nonce = newNonce();
  key = bits.bitArrayToUint8Array(key);
  text = bits.bitArrayToUint8Array(text);
  var data = nacl.secretbox(text, nonce, key);
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
  key = bits.bitArrayToUint8Array(key);
  ciphertext = bits.bitArrayToUint8Array(ciphertext);
  var nonce = ciphertext.slice(0, nonceLen);
  ciphertext = ciphertext.slice(nonceLen);
  var text = nacl.secretbox.open(ciphertext, nonce, key);
  if (text === false) {
    throw new Error('decryption failed');
  }
  return bits.uint8ArrayToBitArray(text);
}
exports.decrypt = decrypt;