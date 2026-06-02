// proto.js — protobuf codec for the Tesla BLE protocol.
//
// V4.4 Phase 3c step 3 of 4. Loads the vendored .proto files at
// runtime via protobuf.js and exposes the message types the BLE
// session needs:
//
//   airgap.proto.RoutableMessage   (universal_message.RoutableMessage)
//   airgap.proto.SessionInfo       (signatures.SessionInfo)
//   airgap.proto.SignatureData     (signatures.SignatureData)
//   airgap.proto.Action            (carServer.Action)
//   airgap.proto.UnsignedMessage   (carServer.UnsignedMessage)
//   airgap.proto.Response          (carServer.Response)
//   airgap.proto.types             — enum lookups (Domain, Tag, etc.)
//
// Why protobuf.js over hand-rolled: every Tesla firmware update can
// add new VehicleAction sub-messages (V4.3 added 5; the pattern
// repeats). With this loader, adding a new command is "drop in the
// updated .proto" — no encoder code per message. Hand-rolling would
// be a real maintenance drag for exactly the path we're going to
// keep extending.
//
// Bundle cost: ~75 KB of vendored protobuf.min.js + ~50 KB of .proto
// files. Trivial on a laptop; the alternative was 500-1000 lines of
// careful hand-rolled binary code.

window.airgap = window.airgap || {};

// loadProto runs once on page init. Caches the protobuf.js Root so
// subsequent calls return the same lookup table without re-parsing
// the .proto files.
//
// The file list is the import closure for the messages we use. Order
// doesn't matter — protobuf.js resolves imports lazily as long as the
// files are reachable from the same root path.
let _rootPromise = null;
async function loadProto() {
    if (_rootPromise) return _rootPromise;
    _rootPromise = (async () => {
        // protobuf.js exposes itself globally as `protobuf` from
        // protobuf.min.js. If it's not present we surface a clear
        // error rather than the confusing "protobuf is not defined".
        if (typeof protobuf === 'undefined') {
            throw new Error('protobuf.min.js failed to load — check the <script> tag');
        }
        const root = await protobuf.load([
            'proto/signatures.proto',
            'proto/universal_message.proto',
            'proto/errors.proto',
            'proto/keys.proto',
            'proto/vcsec.proto',
            'proto/common.proto',
            'proto/managed_charging.proto',
            'proto/vehicle.proto',
            'proto/car_server.proto',
        ]);

        // Message types we'll touch from app.js / session crypto.
        // CarServer.Action is the top-level wrapper for every
        // infotainment command (there's no UnsignedMessage on the
        // CarServer side — VehicleAction lives directly inside Action).
        const RoutableMessage = root.lookupType('UniversalMessage.RoutableMessage');
        const SessionInfo     = root.lookupType('Signatures.SessionInfo');
        const SignatureData   = root.lookupType('Signatures.SignatureData');
        const Action          = root.lookupType('CarServer.Action');
        const Response        = root.lookupType('CarServer.Response');

        // VCSEC has its own UnsignedMessage wrapper for status polls
        // and closure operations. Distinct from the CarServer flow.
        const VCSECUnsignedMessage = root.lookupType('VCSEC.UnsignedMessage');
        const InformationRequest   = root.lookupType('VCSEC.InformationRequest');

        // VCSEC inbound surface — the car's reply to a GET_STATUS or to
        // a closure command. FromVCSECMessage is the top-level wrapper
        // (one of vehicleStatus, commandStatus, …). VehicleStatus is
        // the slice we care about: lock/sleep/closures/presence.
        const FromVCSECMessage = root.lookupType('VCSEC.FromVCSECMessage');
        const VehicleStatus    = root.lookupType('VCSEC.VehicleStatus');

        // Enum lookups so callers can write
        //   airgap.proto.types.Domain.DOMAIN_INFOTAINMENT
        // instead of magic numbers.
        const types = {
            Domain:           root.lookupEnum('UniversalMessage.Domain').values,
            Tag:              root.lookupEnum('Signatures.Tag').values,
            SignatureType:    root.lookupEnum('Signatures.SignatureType').values,
            SessionInfoStatus:root.lookupEnum('Signatures.Session_Info_Status').values,
            MessageFault:     root.lookupEnum('UniversalMessage.MessageFault_E').values,
            OperationStatus:  root.lookupEnum('UniversalMessage.OperationStatus_E').values,
        };

        return {
            root,
            RoutableMessage,
            SessionInfo,
            SignatureData,
            Action,
            Response,
            VCSECUnsignedMessage,
            InformationRequest,
            FromVCSECMessage,
            VehicleStatus,
            types,
        };
    })();
    return _rootPromise;
}

// encodeMessage / decodeMessage are thin wrappers that match the
// shape of the existing airgap helpers. Callers don't need to import
// protobuf.js directly.
function encodeMessage(type, fields) {
    const errMsg = type.verify(fields);
    if (errMsg) throw new Error(`encode ${type.name}: ${errMsg}`);
    const msg = type.create(fields);
    return type.encode(msg).finish();
}

function decodeMessage(type, bytes) {
    return type.decode(bytes);
}

Object.assign(window.airgap, {
    loadProto,
    encodeMessage,
    decodeMessage,
});
