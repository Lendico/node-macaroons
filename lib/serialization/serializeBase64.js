var sjcl = require("sjcl");

var util = require("../util");
var constants = require("../constants");
var serializeJson = require("./serializeJson");

function zeros(num) { return Array.apply(null, Array(num)).map(function() {return '0';}).join(""); }
function numberToHex(num) { return ("0000" + (num >>> 0).toString(constants.RADIX)).slice(-constants.PACKET_PREFIX_LENGTH); }

function serializeStringPairToBinary(keyValue) {
  var caveatStringContent = keyValue[0] + " " + keyValue[1] + "\n";
  var caveatLength = caveatStringContent.length + constants.PACKET_PREFIX_LENGTH;
  if(0 <= caveatLength && caveatLength >= (constants.PACKET_MAX_LENGTH)){ throw new Error("Data is too long for a binary packet."); }

  return sjcl.codec.utf8String.toBits(numberToHex(caveatLength) + caveatStringContent);
}

function serializeBinaryPairToBinary(keyValue){
  var keyPartBits = sjcl.codec.utf8String.toBits(keyValue[0] + " ");
  var footerBits = sjcl.codec.utf8String.toBits("\n");
  var contents = sjcl.bitArray.concat(keyPartBits, sjcl.bitArray.concat(keyValue[1], footerBits));
  var caveatLength = (sjcl.bitArray.bitLength(contents) / 8) + constants.PACKET_PREFIX_LENGTH;

  if(0 <= caveatLength && caveatLength >= (constants.PACKET_MAX_LENGTH)){ throw new Error("Data is too long for a binary packet."); }

  var headerBits = sjcl.codec.utf8String.toBits(numberToHex(caveatLength));
  return sjcl.bitArray.concat(headerBits, contents);
}

function detailsWithoutSignatureBinary(m) {
  var exportedMacaroon = serializeJson.serialize(m);

  var fullList = util.shallowFlatten(exportedMacaroon.caveats.map(function (caveat) {
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

function removeHeader(line) { return line.slice(constants.PACKET_PREFIX_LENGTH);}

exports.details = function(m) {
  var fullMacaroonBits = sjcl.bitArray.concat(
    detailsWithoutSignatureBinary(m), 
    serializeStringPairToBinary(["signature", sjcl.codec.hex.fromBits(m.signatureRaw())]));

  var details = sjcl.codec.utf8String.fromBits(fullMacaroonBits, true, true);

  return details.split("\n").map(removeHeader).join("\n");;
};