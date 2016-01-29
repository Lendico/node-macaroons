/*jslint indent: 2, node: true, nomen: true, plusplus: true, todo: true, vars: true, white: true */
/*global Uint8Array,nacl,sjcl */
var nacl = require("tweetnacl");
var sjcl = require("sjcl");

var Macaroon = require("./lib/").Macaroon;
var asserts = require("./lib/asserts");
var hash = require("./lib/hash");
var bits = require("./lib/bits");
var util = require("./lib/util");
var caveat = require("./lib/caveat");

var serializeJson = require("./lib/serialization/serializeJson");
var serializeBase64 = require("./lib/serialization/serializeBase64");

var deserializeJson = require("./lib/deserialization/deserializeJson");
var deserializeBase64 = require("./lib/deserialization/deserializeBase64");

function macaroon() {
  'use strict';
  var exports = {};

  // newMacaroon returns a new macaroon with the given
  // root key, identifier and location.
  // The root key must be an sjcl bitArray.
  // TODO accept string, Buffer, for root key?
  exports.newMacaroon = function(rootKey, id, loc) {
    asserts.assertString(loc, 'macaroon location');
    asserts.assertString(id, 'macaroon identifier');
    asserts.assertUint8Array(rootKey, 'macaroon root key');

    return Macaroon({
      _caveats: [],
      _location: loc,
      _identifier: id,
      _signature: hash.keyedHash(hash.makeKey(rootKey), sjcl.codec.utf8String.toBits(id))
    });
  };

  // export converts a macaroon or array of macaroons
  // to the exported object form, suitable for encoding as JSON.
  exports.export = serializeJson.serialize;
  exports.serialize = serializeBase64.serialize;
  exports.details = serializeBase64.details;

  // import converts an object as deserialised from
  // JSON to a macaroon. It also accepts an array of objects,
  // returning the resulting array of macaroons.
  exports.import = deserializeJson.deserialize;
  exports.deserialize = deserializeBase64.deserialize;

  // discharge gathers discharge macaroons for all the third party caveats
  // in m (and any subsequent caveats required by those) calling getDischarge to
  // acquire each discharge macaroon.
  //
  // On success, it calls onOk with an array argument
  // holding m as the first element, followed by
  // all the discharge macaroons. All the discharge macaroons
  // will be bound to the primary macaroon.
  //
  // On failure, it calls onError with any error encountered.
  //
  // The getDischarge argument should be a function that
  // is passed five parameters: the value of m.location(),
  // the location of the third party, the third party caveat id,
  // all strings, a callback function to call with the acquired
  // macaroon on success, and a callback function to call with
  // any error on failure.
  exports.discharge = function(m, getDischarge, onOk, onError) {
    var primarySig = m.signature();
    var firstPartyLocation = m.location();

    function dischargeCaveats(mac, callback){
      util.asyncMap(
        mac.getCaveats().filter(caveat.isCaveatThirdParty),
        function (cav, iterFn) {
          getDischarge(
            firstPartyLocation,
            cav._location,
            cav._identifier,
            function (dischargeMac) { dischargeCaveats(dischargeMac.bind(primarySig), iterFn);},
            iterFn);
        },
        function (err, discharges) { return callback(err, [mac].concat(discharges)); });
    }

    dischargeCaveats(m, function (err, newDischarges) {
      return err ? onError(err) : onOk(util.deepFlatten(newDischarges));
    });
  };

  return exports;
}

module.exports = macaroon();
