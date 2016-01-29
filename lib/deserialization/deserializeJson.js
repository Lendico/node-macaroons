var sjcl = require("sjcl");

var asserts = require("../asserts");

var Macaroon = require("../index").Macaroon;

function isMacJsonThirdPartyCaveat(jsonCav){ return jsonCav.vid !== undefined; }

function deserialize(obj) {
  if (obj.constructor === Array) { return obj.map(deserialize); }

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
}

exports.deserialize = deserialize;