
// Macaroon defines the macaroon object. It is not exported
// as a constructor - newMacaroon should be used instead.
function Verifier() {
  var _checkList = [];

  var _verifier = {
    addCaveatCheck: function(fun) {
      _checkList.push(fun);
      return _verifier;
    },
    createCheck: function() {   
      return function (cav) { 
        return _checkList.find(function (fn) {
          return fn(cav);
        }) ? null : 'condition "' + cav + '" not met';
      }
    }
  };

  return _verifier;
}

exports.Verifier = Verifier;

exports.newVerifier = function(check) {
  return Verifier();
};