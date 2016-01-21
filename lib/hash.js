var sjcl = require("sjcl");
var keyGen = sjcl.codec.utf8String.toBits('macaroons-key-generator');

var bits = require("./bits");


// keyedHasher returns a keyed hash using the given
// key, which must be an sjcl bitArray.
var keyedHasher = function(key) {
  return new sjcl.misc.hmac(key, sjcl.hash.sha256);
};

function keyedHash2(key, d1, d2) {
  if (d1 === null) {
    return keyedHash(key, d2);
  }
  var h1 = keyedHash(key, d1);
  var h2 = keyedHash(key, d2);
  return keyedHash(key, sjcl.bitArray.concat(h1, h2));
}
exports.keyedHash2 = keyedHash2;

// keyedHash returns the keyed hash of the given
// data. Both key and data must be sjcl bitArrays.
// It returns the hash as an sjcl bitArray.
function keyedHash(key, data) {
  var h = keyedHasher(key);
  h.update(data);
  return h.digest();
};
exports.keyedHash = keyedHash;

// makeKey returns a fixed length key suitable for use as a nacl secretbox
// key. It accepts a Uint8Array and returns a sjcl bitArray.
function makeKey(variableKey) {
  variableKey = bits.uint8ArrayToBitArray(variableKey);
  return keyedHash(keyGen, variableKey);
}
exports.makeKey = makeKey;

// 32 zero bytes.
var zeroKey = sjcl.codec.hex.toBits('0000000000000000000000000000000000000000000000000000000000000000');

// bindForRequest binds the given macaroon
// to the given signature of its parent macaroon.
function bindForRequest(rootSig, dischargeSig) {
  if (sjcl.bitArray.equal(rootSig, dischargeSig)) {
    return rootSig;
  }
  return keyedHash2(zeroKey, rootSig, dischargeSig);
}
exports.bindForRequest = bindForRequest;