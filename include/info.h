#pragma once

#include <stdint.h>
#include "utils.h"


// FIDO versions
#define FIDO_VERSION_U2F_V2                                 BITFIELD(0)
#define FIDO_VERSION_FIDO_2_0                               BITFIELD(1)
#define FIDO_VERSION_FIDO_2_1                               BITFIELD(2)
#define FIDO_VERSION_FIDO_2_1_PRE                           BITFIELD(3)
typedef uint8_t fido_cbor_version_t;

// FIDO extensions
#define FIDO_EXTENSION_CRED_PROTECT                         BITFIELD(0)
#define FIDO_EXTENSION_CRED_BLOB                            BITFIELD(1)
#define FIDO_EXTENSION_LARGE_BLOB_KEY                       BITFIELD(2)
#define FIDO_EXTENSION_MIN_PIN_LENGTH                       BITFIELD(3)
#define FIDO_EXTENSION_HMAC_SECRET                          BITFIELD(4)
typedef uint8_t fido_cbor_extension_t;

// FIDO transports
#define FIDO_TRANSPORT_USB                                  BITFIELD(0)
#define FIDO_TRANSPORT_NFC                                  BITFIELD(1)
#define FIDO_TRANSPORT_BLE                                  BITFIELD(2)
#define FIDO_TRANSPORT_INTERNAL                             BITFIELD(3)
typedef uint8_t fido_cbor_transport_t;

// FIDO options
#define FIDO_OPTION_PLAT                                    BITFIELD( 0)
#define FIDO_OPTION_RK                                      BITFIELD( 1)
#define FIDO_OPTION_CLIENT_PIN                              BITFIELD( 2)
#define FIDO_OPTION_UP                                      BITFIELD( 3)
#define FIDO_OPTION_UV                                      BITFIELD( 4)
#define FIDO_OPTION_PIN_UV_AUTH_TOKEN                       BITFIELD( 5)
#define FIDO_OPTION_NO_MC_GA_PERMISSIONS_WITH_CLIENT_PIN    BITFIELD( 6)
#define FIDO_OPTION_LARGE_BLOBS                             BITFIELD( 7)
#define FIDO_OPTION_EP                                      BITFIELD( 8)
#define FIDO_OPTION_BIO_ENROLL                              BITFIELD( 9)
#define FIDO_OPTION_USER_VERIFICATION_MGMT_PREVIEW          BITFIELD(10)
#define FIDO_OPTION_UV_BIO_ENROLL                           BITFIELD(11)
#define FIDO_OPTION_AUTHNR_CONFIG                           BITFIELD(12)
#define FIDO_OPTION_UV_ACFG                                 BITFIELD(13)
#define FIDO_OPTION_CRED_MGMT                               BITFIELD(14)
#define FIDO_OPTION_CREDENTIAL_MANAGEMENT_PREVIEW           BITFIELD(15)
#define FIDO_OPTION_SET_MIN_PIN_LENGTH                      BITFIELD(16)
#define FIDO_OPTION_MAKE_CRED_UV_NOT_RQD                    BITFIELD(17)
#define FIDO_OPTION_ALWAYS_UV                               BITFIELD(18)
typedef uint32_t fido_cbor_options_t;

// FIDO pin protocols
#define FIDO_PIN_PROTOCOL_1                                 BITFIELD(0)
#define FIDO_PIN_PROTOCOL_2                                 BITFIELD(1)
typedef uint8_t fido_cbor_pin_protocol_t;

// FIDO credential generation algorithms
// TODO: There are a lot of possibly supported algorithms
// See https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialparameters
#define FIDO_CREDENTIAL_GENERATION_ES256                    BITFIELD(0)
#define FIDO_CREDENTIAL_GENERATION_EdDSA                    BITFIELD(1)
typedef uint8_t fido_cbor_algorithm_t;

// According to the Webauthn Standard: https://w3c.github.io/webauthn/#typedefdef-cosealgorithmidentifier
// For COSE identifiers see https://www.iana.org/assignments/cose/cose.xhtml#algorithms
// EdDSA with Ed25519 as curve.
#define COSE_ALGORITHM_EdDSA    (-8)
// P-256 curve.
#define COSE_ALGORITHM_ES256    (-7)

// See https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo
typedef struct fido_cbor_info {
    fido_cbor_version_t      versions;        /* list of supported versions */
    fido_cbor_extension_t    extensions;     /* list of supported extensions */
    fido_cbor_transport_t    transports;     /* list of supported transports */
    unsigned char            aaguid[16];     /* aaguid */
    fido_cbor_options_t      options;        /* list of supported options */
    uint64_t                 maxmsgsize;     /* maximum message size */
    // TODO: How to support authenticator preference?
    fido_cbor_pin_protocol_t protocols;      /* supported pin protocols */
    // TODO: How to support authenticator preference?
    fido_cbor_algorithm_t    algorithms;     /* list of supported algorithms */
    uint64_t                 maxcredcntlst;  /* max credentials in list */
    uint64_t                 maxcredidlen;   /* max credential ID length */
    uint64_t                 fwversion;      /* firmware version */
    uint64_t                 maxcredbloblen; /* max credBlob length */
    uint64_t                 maxlargeblob;   /* max largeBlob array length */
} fido_cbor_info_t;

void fido_cbor_info_reset(fido_cbor_info_t *ci);
