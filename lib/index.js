var nacl = require("tweetnacl");
var sjcl = require("sjcl");

var asserts = require("./asserts");
var bits = require("./bits");
var encryption = require("./encryption");
var hash = require("./hash");

function quote(s) {
  return JSON.stringify(s);
}

// Macaroon defines the macaroon object. It is not exported
// as a constructor - newMacaroon should be used instead.
var Macaroon = function() {
  return this;
};

// bound returns a copy of the macaroon prepared for
// being used to discharge a macaroon with the given signature,
// which should be a Uint8Array.
Macaroon.prototype.bind = function(sig) {
  var uint8Sig = bits.uint8ArrayToBitArray(sig);
  this._signature = hash.bindForRequest(uint8Sig, this._signature);
};

// caveats returns a list of all the caveats in the macaroon.
Macaroon.prototype.getCaveats = function() {
  return this._caveats;
};

// clone returns a copy of the macaroon. Any caveats added
// to the returned macaroon will not reflect the original.
Macaroon.prototype.clone = function() {
  var m = new Macaroon();
  m._signature = this._signature;
  m._identifier = this._identifier;
  m._location = this._location;
  m._caveats = this._caveats.slice();
  return m;
};

// location returns the location of the macaroon
// as a string.
Macaroon.prototype.location = function() {
  return this._location;
};

// id returns the macaroon's identifier as a string.
Macaroon.prototype.id = function() {
  return this._identifier;
};

// signature returns the macaroon's signature as a Uint8Array.
Macaroon.prototype.signature = function() {
  return bits.bitArrayToUint8Array(this._signature);
};

// addThirdPartyCaveat adds a third-party caveat to the macaroon,
// using the given shared root key, caveat id and location hint.
// The caveat id should encode the root key in some
// way, either by encrypting it with a key known to the third party
// or by holding a reference to it stored in the third party's
// storage.
// The root key must be an sjcl bitArray; the other arguments
// must be strings.
Macaroon.prototype.addThirdPartyCaveat = function(rootKey, caveatId, loc) {
  asserts.assertUint8Array(rootKey, 'caveat root key');
  asserts.assertString(caveatId, 'caveat id');
  asserts.assertString(loc, 'caveat location');
  var verificationId = encryption.encrypt(this._signature, hash.makeKey(rootKey));
  var uint8VerificationId = bits.bitArrayToUint8Array(verificationId);
  this.addCaveat(caveatId, uint8VerificationId, loc);
};

// addFirstPartyCaveat adds a caveat that will be verified
// by the target service. The caveat id must be a string.
Macaroon.prototype.addFirstPartyCaveat = function(caveatId) {
  this.addCaveat(caveatId, null, null);
};

// addCaveat adds a first or third party caveat. The caveat id must be
// a string. For a first party caveat, the verification id and the
// location must be null, otherwise the verification id must be
// a sjcl bitArray and the location must be a string.
Macaroon.prototype.addCaveat = function(caveatId, verificationId, loc) {
  asserts.assertString(caveatId, 'macaroon caveat id');

  if (verificationId !== null) {
    asserts.assertString(loc, 'macaroon caveat location');
    asserts.assertUint8Array(verificationId, 'macaroon caveat verification id');
  }

  var bitArrayVerificationId = verificationId !== null ? bits.uint8ArrayToBitArray(verificationId) : null;

  var cav = {
    _identifier: caveatId,
    _vid: bitArrayVerificationId,
    _location: verificationId !== null ? loc : null,
  }

  this._caveats.push(cav);
  this._signature = hash.keyedHash2(this._signature, bitArrayVerificationId, sjcl.codec.utf8String.toBits(caveatId));
};

// Verify verifies that the receiving macaroon is valid.
// The root key must be the same that the macaroon was originally
// minted with. The check function is called to verify each
// first-party caveat - it should return an error if the
// condition is not met, or null if the caveat is satisfied.
//
// The discharge macaroons should be provided as an array in discharges.
//
// Verify throws an exception if the verification fails.
Macaroon.prototype.verify = function(rootKey, check, discharges) {
  rootKey = hash.makeKey(rootKey);
  var dischargesArr = discharges || [];
  var used = dischargesArr.map(function () { return 0; });
  this._verify(this._signature, rootKey, check, dischargesArr, used);
  dischargesArr.forEach(function(dm, i) {
      if (used[i] === 0) {
          throw new Error('discharge macaroon ' + quote(dm.id()) + ' was not used');
      }
      if (used[i] !== 1) {
          // Should be impossible because of check in verify1, but be defensive.
          throw new Error('discharge macaroon ' + quote(dm.id()) + ' was used more than once');
      }
  });
};

Macaroon.prototype._verify = function(rootSig, rootKey, check, discharges, used) {
  var caveatSig = hash.keyedHash(rootKey, sjcl.codec.utf8String.toBits(this.id()));
  this._caveats.forEach(function(cav) {
    if (cav._vid !== null) {
      var cavKey = encryption.decrypt(caveatSig, cav._vid);
      var found = false;
      for (var di = 0; di < discharges.length; di++) {
        var dm = discharges[di];
        if (dm.id() === cav._identifier) {
          found = true;
          // It's important that we do this before calling _verify,
          // as it prevents potentially infinite recursion.
          used[di]++;
          if (used[di] > 1) {
            throw new Error('discharge macaroon ' + quote(dm.id()) + ' was used more than once ');
          }
          dm._verify(rootSig, cavKey, check, discharges, used);
          break;
        }
      }
      if (!found) {
        throw new Error('cannot find discharge macaroon for caveat ' + quote(cav._identifier));
      }
    } else {
      var err = check(cav._identifier);
      if (err) {
        throw new Error(err);
      }
    }
    caveatSig = hash.keyedHash2(caveatSig, cav._vid, cav._identifier);
  });
  var boundSig = hash.bindForRequest(rootSig, caveatSig);
  if (!sjcl.bitArray.equal(boundSig, this._signature)) {
    throw new Error('signature mismatch after caveat verification');
  }
};

exports.Macaroon = Macaroon;