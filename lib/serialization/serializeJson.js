var sjcl = require("sjcl");

var caveat = require("../caveat");

function serialize(m) {
  if (m.constructor === Array) { return m.map(serialize); }

  function firstPartyCaveatObj(cav){ return { cid: cav._identifier }; }

  function thirdPartyCaveatObj(cav){ 
    return {  cid: cav._identifier, vid: sjcl.codec.base64.fromBits(cav._vid, true, true), cl: cav._location }; 
  }

  return {
    location: m.location(),
    identifier: m.id(),
    signature: sjcl.codec.hex.fromBits(m.signatureRaw()),
    caveats: m.getCaveats().map(function(cav) {
      return (caveat.isCaveatThirdParty(cav) ? thirdPartyCaveatObj : firstPartyCaveatObj)(cav);
    })
  };
};
exports.serialize = serialize;