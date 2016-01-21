// assertUint8Array asserts that the given object
// is a Uint8array, and fails with an exception including
// "what" if it is not.
function assertUint8Array(obj, what) {
  if (!(obj instanceof Uint8Array)) {
    throw new Error('invalid ' + what + ': ' + obj);
  }
}
exports.assertUint8Array = assertUint8Array;

// assertString asserts that the given object
// is a string, and fails with an exception including
// "what" if it is not.
function assertString(obj, what) {
  if (typeof obj !== 'string') {
    throw new Error('invalid ' + what + ': ' + obj);
  }
}
exports.assertString = assertString;