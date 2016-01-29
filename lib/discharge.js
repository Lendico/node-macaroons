var util = require("./util");
var caveat = require("./caveat");

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