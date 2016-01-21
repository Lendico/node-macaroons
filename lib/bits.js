var sjcl = require("sjcl");
var nacl = require("tweetnacl");

// bitArrayToUint8Array returns the sjcl bitArray a
// converted to a Uint8Array as used by nacl.
function bitArrayToUint8Array(a) {
  // TODO I'm sure there's a more efficient way to do this.
  return nacl.util.decodeBase64(sjcl.codec.base64.fromBits(a));
}
exports.bitArrayToUint8Array = bitArrayToUint8Array;

// uint8ArrayToBitArray returns the Uint8Array a
// as used by nacl as an sjcl bitArray.
function uint8ArrayToBitArray(a) {
  return sjcl.codec.base64.toBits(nacl.util.encodeBase64(a));
}
exports.uint8ArrayToBitArray = uint8ArrayToBitArray;