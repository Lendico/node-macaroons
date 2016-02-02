
// Macaroon defines the macaroon object. It is not exported
// as a constructor - newMacaroon should be used instead.
function Verifier(macaroon) {
  var _checkList = [];

  var _macaroon = macaroon || null;
  var _discharges = [];
  var _secret = null;

  function createCheck() {   
    return function (cav) { 
      return _checkList.find(function (fn) {
        return fn(cav);
      }) ? null : 'condition "' + cav + '" not met';
    }
  }

  var _verifier = {
    addCaveatCheck: function(fun) {
      _checkList.push(fun);
      return _verifier;
    },
    macaroon: function(macaroon) {
      _macaroon = macaroon;
      return _verifier;
    },
    discharges: function(discharges) {
      _discharges = discharges;
      return _verifier;
    },
    secret: function(secret) {
      _secret = secret;
      return _verifier;
    },
    verify: function () {
      _macaroon.verify(_secret, createCheck(), _discharges);
    },
    isVerified: function () {
      try {
        _macaroon.verify(_secret, createCheck(), _discharges);
      }catch(e){
        return false;
      }
      return true;
    }
  };

  return _verifier;
}

exports.Verifier = Verifier;

exports.newVerifier = function(macaroon) {
  return Verifier(macaroon);
};