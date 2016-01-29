var sjcl = require("sjcl");

var deserializeJson = require("./deserializeJson");
var constants = require("../constants");

function setAndReturn(obj, key, value) {
  obj[key] = value;
  return obj;
}

function sliceStringFromBitArray(bitArray, start, end){
  return sjcl.codec.utf8String.fromBits(sjcl.bitArray.bitSlice(bitArray, start * constants.BYTE_SIZE, end * constants.BYTE_SIZE));
}

function findChar(bitArray, searchChar) {
  var charLength = (sjcl.bitArray.bitLength(bitArray) / constants.BYTE_SIZE);

  for(var i = 0; i < charLength; ++i){
    var curChar = sliceStringFromBitArray(bitArray, i, i + 1);
    if(curChar === searchChar){ return i; }
  }
}

function getNextBits(macBits){
  var locationAfterSize = constants.BYTE_SIZE * constants.PACKET_PREFIX_LENGTH;
  var sizeBytes = parseInt(sliceStringFromBitArray(macBits, 0, constants.PACKET_PREFIX_LENGTH), 16);

  var locationAtEndOfCaveat = constants.BYTE_SIZE * sizeBytes;

  var charSpaceIndex = findChar(sjcl.bitArray.bitSlice(macBits, locationAfterSize, locationAtEndOfCaveat), " ");
  var charLocationOfSpace = constants.PACKET_PREFIX_LENGTH + charSpaceIndex;
  var key = sliceStringFromBitArray(macBits, constants.PACKET_PREFIX_LENGTH, charLocationOfSpace);

  // -1 for newline
  var valueBits = sjcl.bitArray.bitSlice(macBits, (charLocationOfSpace + 1) * constants.BYTE_SIZE, (sizeBytes - 1) * constants.BYTE_SIZE)    

  return {
    keyString: key,
    valueBits: valueBits,
    nextBits: sjcl.bitArray.bitSlice(macBits, locationAtEndOfCaveat)
  };
}

function getMacaroonPartsFromMacaroonBit(macBits) {
  var curBits = macBits;
  var macaroonParts = [];

  while(curBits.length){
    var bitsObj = getNextBits(curBits);
    var key = bitsObj.keyString;
    var valueBits = bitsObj.valueBits;

    if(bitsObj.nextBits === curBits) { throw new Error("Deserialization Error"); }

    curBits = bitsObj.nextBits;
    macaroonParts.push({keyString: key, valueBits: valueBits});
  }

  return macaroonParts;
}

exports.deserialize = function (macHex) {

  var macBits = sjcl.codec.base64.toBits(macHex, true);

  var macaroonParts = getMacaroonPartsFromMacaroonBit(macBits);

  var macaroonImport = macaroonParts
    .reduce(function (aggObj, macPartObj) {

      if(macPartObj.keyString === "location"){ return setAndReturn(aggObj, "location", sjcl.codec.utf8String.fromBits(macPartObj.valueBits)); }
      if(macPartObj.keyString === "identifier"){ return setAndReturn(aggObj, "identifier", sjcl.codec.utf8String.fromBits(macPartObj.valueBits)); }
      if(macPartObj.keyString === "signature"){ return setAndReturn(aggObj, "signature", sjcl.codec.hex.fromBits(macPartObj.valueBits)); }
      if(macPartObj.keyString === "cid"){ 
        aggObj.caveats.push({cid: sjcl.codec.utf8String.fromBits(macPartObj.valueBits)});
        return aggObj;
      }
      if(macPartObj.keyString === "vid"){ 
        var lastCaveat = macPartObj.caveats[macPartObj.caveats.length - 1];
        lastCaveat.vid = sjcl.codec.utf8String.fromBits(macPartObj.valueBits);
        aggObj.caveats[macPartObj.caveats.length - 1] = lastCaveat;
        return aggObj;
      }
      if(macPartObj.keyString === "cl"){ 
        var lastCaveat = macPartObj.caveats[macPartObj.caveats.length - 1];
        lastCaveat.cl = sjcl.codec.utf8String.fromBits(macPartObj.valueBits);
        aggObj.caveats[macPartObj.caveats.length - 1] = lastCaveat;
        return aggObj;  
      }
        
      return aggObj;
    }, {caveats: []});

  return deserializeJson.deserialize(macaroonImport);
};