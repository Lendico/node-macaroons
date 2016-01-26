/*jslint indent: 2, node: true, nomen: true, plusplus: true, todo: true, vars: true, white: true */
/*global Uint8Array,nacl,sjcl */
var nacl = require("tweetnacl");
var sjcl = require("sjcl");

var Macaroon = require("./lib/").Macaroon;
var asserts = require("./lib/asserts");
var hash = require("./lib/hash");

function macaroon() {
  'use strict';
  var exports = {};

  function shallowFlatten(list) { return [].concat.apply([], list); }
  function deepFlatten(maybeList){ 
    return Array.isArray(maybeList) ? shallowFlatten(maybeList.map(deepFlatten)) : maybeList; 
  }

  function isMacJsonThirdPartyCaveat(jsonCav){ return jsonCav.vid !== undefined; }
  function isMacThirdPartyCaveat(cav){ return cav._vid !== null; }

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

  // import converts an object as deserialised from
  // JSON to a macaroon. It also accepts an array of objects,
  // returning the resulting array of macaroons.
  exports.import = function(obj) {
    if (obj.constructor === Array) { return obj.map(exports.import); }

    asserts.assertString(obj.location, 'macaroon location');
    asserts.assertString(obj.identifier, 'macaroon identifier');

    function toFirstPartyCaveatObj(jsonCav) {
      asserts.assertString(jsonCav.cid, 'caveat id');

      return { _identifier: jsonCav.cid, _location: null, _vid: null };
    }

    function toThirdPartyCaveatObj(jsonCav) {
      asserts.assertString(jsonCav.cid, 'caveat id');
      asserts.assertString(jsonCav.vid, 'caveat verification id');
      asserts.assertString(jsonCav.cl, 'caveat location');

      return { _identifier: jsonCav.cid, _location: jsonCav.cl, _vid: sjcl.codec.base64.toBits(jsonCav.vid, true) };
    }

    return Macaroon({
      _signature: sjcl.codec.hex.toBits(obj.signature),
      _location: obj.location,
      _identifier: obj.identifier,
      _caveats: obj.caveats.map(function(jsonCav) {
        return (isMacJsonThirdPartyCaveat(jsonCav) ? toThirdPartyCaveatObj : toFirstPartyCaveatObj)(jsonCav);
      })
    });
  };

  // export converts a macaroon or array of macaroons
  // to the exported object form, suitable for encoding as JSON.
  function exportFn(m) {
    if (m.constructor === Array) { return m.map(exportFn); }

    function firstPartyCaveatObj(cav){ return { cid: cav._identifier }; }

    function thirdPartyCaveatObj(cav){ 
      return {  cid: cav._identifier, vid: sjcl.codec.base64.fromBits(cav._vid, true, true), cl: cav._location }; 
    }

    return {
      location: m.location(),
      identifier: m.id(),
      signature: sjcl.codec.hex.fromBits(m.signatureRaw()),
      caveats: m.getCaveats().map(function(cav) {
        return (isMacThirdPartyCaveat(cav) ? thirdPartyCaveatObj : firstPartyCaveatObj)(cav);
      })
    };
  };

  exports.export = exportFn;

  var PACKET_PREFIX_LENGTH = 4;
  var RADIX = 16;
  var PACKET_MAX_LENGTH = 65535;

  function zeros(num) { return Array.apply(null, Array(num)).map(function() {return '0';}).join(""); }
  function numberToHex(num) { return ("0000" + (num >>> 0).toString(RADIX)).slice(-PACKET_PREFIX_LENGTH); }

  function serializeStringPairToBinary(keyValue) {
    var caveatStringContent = keyValue[0] + " " + keyValue[1] + "\n";
    var caveatLength = caveatStringContent.length + PACKET_PREFIX_LENGTH;
    if(0 <= caveatLength && caveatLength >= (65535)){ throw new Error("Data is too long for a binary packet."); }

    return sjcl.codec.utf8String.toBits(numberToHex(caveatLength) + caveatStringContent);
  }

  function serializeBinaryPairToBinary(keyValue){
    var keyPartBits = sjcl.codec.utf8String.toBits(keyValue[0] + " ");
    var footerBits = sjcl.codec.utf8String.toBits("\n");
    var contents = sjcl.bitArray.concat(keyPartBits, sjcl.bitArray.concat(keyValue[1], footerBits));
    var caveatLength = (sjcl.bitArray.bitLength(contents) / 8) + PACKET_PREFIX_LENGTH;

    if(0 <= caveatLength && caveatLength >= (65535)){ throw new Error("Data is too long for a binary packet."); }

    var headerBits = sjcl.codec.utf8String.toBits(numberToHex(caveatLength));
    return sjcl.bitArray.concat(headerBits, contents);
  }

  function detailsWithoutSignatureBinary(m) {
    var exportedMacaroon = exportFn(m);

    var fullList = shallowFlatten(exportedMacaroon.caveats.map(function (caveat) {
      return [['cid', caveat.cid]].concat(caveat.vid ? [['vid', caveat.vid], ['cl', caveat.cl]] : []);
    }));

    var pairs = [
      ["location", exportedMacaroon.location], 
      ["identifier", exportedMacaroon.identifier]]
      .concat(fullList);

    return pairs
      .map(serializeStringPairToBinary)
      .reduce(sjcl.bitArray.concat, sjcl.codec.utf8String.toBits(""));
  };

  exports.serialize = function(m) {
    var fullMacaroonBits = sjcl.bitArray.concat(
      detailsWithoutSignatureBinary(m), 
      serializeBinaryPairToBinary(["signature", m.signatureRaw()]));

    return sjcl.codec.base64.fromBits(fullMacaroonBits, true, true);
  };

  exports.details = function(m) {
    function removeHeader(line) { return line.slice(PACKET_PREFIX_LENGTH);}

    var fullMacaroonBits = sjcl.bitArray.concat(
      detailsWithoutSignatureBinary(m), 
      serializeStringPairToBinary(["signature", sjcl.codec.hex.fromBits(m.signatureRaw())]));

    var details = sjcl.codec.utf8String.fromBits(fullMacaroonBits, true, true);

    var doctoredDetails = details.split("\n").map(removeHeader).join("\n");

    return doctoredDetails;
  };

  function asyncMap(list, itFun, resFn) {
    var revList = list.reverse();
    var resultList = [];

    function runAsyncIteration(err, result) {
      resultList.push(result);
      return (err || !revList.length) ? resFn(err, resultList) : itFun(revList.pop(), runAsyncIteration);
    }

    return !revList.length ? resFn(null, resultList) : itFun(revList.pop(), runAsyncIteration);
  }

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
      asyncMap(
        mac.getCaveats().filter(isMacThirdPartyCaveat),
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
      return err ? onError(err) : onOk(deepFlatten(newDischarges));
    });
  };

  return exports;
}

module.exports = macaroon();
