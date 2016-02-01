/*jslint indent: 2, node: true, nomen: true, plusplus: true, todo: true, vars: true, white: true */
/*global Uint8Array,nacl,sjcl */

function macaroon() {
  'use strict';

  return {
    // newMacaroon returns a new macaroon with the given
    // root key, identifier and location.
    // The root key must be an sjcl bitArray.
    // TODO accept string, Buffer, for root key?
    newMacaroon: require("./lib").newMacaroon,
    newVerifier: require("./lib/verifier").newVerifier,
    // export converts a macaroon or array of macaroons
    // to the exported object form, suitable for encoding as JSON.
    export: require("./lib/serialization/serializeJson").serialize,
    serialize: require("./lib/serialization/serializeBase64").serialize,
    details: require("./lib/serialization/serializeBase64").details,

    // import converts an object as deserialised from
    // JSON to a macaroon. It also accepts an array of objects,
    // returning the resulting array of macaroons.
    import: require("./lib/deserialization/deserializeJson").deserialize,
    deserialize: require("./lib/deserialization/deserializeBase64").deserialize,

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
    discharge: require("./lib/discharge").discharge
  };
}

module.exports = macaroon();
