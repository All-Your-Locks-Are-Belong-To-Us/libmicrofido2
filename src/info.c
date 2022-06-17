#include "info.h"
#include "fido.h"

#include <string.h>
#include "cb0r.h"
#include "cbor.h"

#define CBOR_MEMCMP(el, el_start, cmp) (el->length == sizeof(cmp) && !memcmp_progmem(el_start, cmp, sizeof(cmp)))
#define CBOR_STR_MEMCMP(el, cmp) (CBOR_MEMCMP(el, el->start + el->header, cmp))

// versions
static const char fido_2_1_version[] PROGMEM_MARKER        = {'F', 'I', 'D', 'O', '_', '2', '_', '1'};
static const char fido_2_0_version[] PROGMEM_MARKER        = {'F', 'I', 'D', 'O', '_', '2', '_', '0'};
static const char fido_2_1_pre_version[] PROGMEM_MARKER    = {'F', 'I', 'D', 'O', '_', '2', '_', '1', '_', 'P', 'R', 'E'};
static const char fido_u2f_v2_version[] PROGMEM_MARKER     = {'U', '2', 'F', '_', 'V', '2'};

// extensions
static const char fido_extension_cred_blob[] PROGMEM_MARKER       = {'c', 'r', 'e', 'd', 'B', 'l', 'o', 'b'};
static const char fido_extension_hmac_secret[] PROGMEM_MARKER     = {'h', 'm', 'a', 'c', '-', 's', 'e', 'c', 'r', 'e', 't'};
static const char fido_extension_cred_protect[] PROGMEM_MARKER    = {'c', 'r', 'e', 'd', 'P', 'r', 'o', 't', 'e', 'c', 't'};
static const char fido_extension_large_blob_key[] PROGMEM_MARKER  = {'l', 'a', 'r', 'g', 'e', 'B', 'l', 'o', 'b', 'K', 'e', 'y'};
static const char fido_extension_min_pin_length[] PROGMEM_MARKER  = {'m', 'i', 'n', 'P', 'i', 'n', 'L', 'e', 'n', 'g', 't', 'h'};

// options
static const char fido_option_plat[] PROGMEM_MARKER                                 = {'p', 'l', 'a', 't'};
static const char fido_option_rk[] PROGMEM_MARKER                                   = {'r', 'k'};
static const char fido_option_client_pin[] PROGMEM_MARKER                           = {'c', 'l', 'i', 'e', 'n', 't', 'P', 'i', 'n'};
static const char fido_option_up[] PROGMEM_MARKER                                   = {'u', 'p'};
static const char fido_option_uv[] PROGMEM_MARKER                                   = {'u', 'v'};
static const char fido_option_pin_uv_auth_token[] PROGMEM_MARKER                    = {'p', 'i', 'n', 'U', 'v', 'A', 'u', 't', 'h', 'T', 'o', 'k', 'e', 'n'};
static const char fido_option_no_mc_ga_permissions_with_client_pin[] PROGMEM_MARKER = {'n', 'o', 'M', 'c', 'G', 'a', 'P', 'e', 'r', 'm', 'i', 's', 's', 'i', 'o', 'n', 's', 'W', 'i', 't', 'h', 'C', 'l', 'i', 'e', 'n', 't', 'P', 'i', 'n'};
static const char fido_option_large_blobs[] PROGMEM_MARKER                          = {'l', 'a', 'r', 'g', 'e', 'B', 'l', 'o', 'b', 's'};
static const char fido_option_ep[] PROGMEM_MARKER                                   = {'e', 'p'};
static const char fido_option_bio_enroll[] PROGMEM_MARKER                           = {'b', 'i', 'o', 'E', 'n', 'r', 'o', 'l', 'l'};
static const char fido_option_user_verification_mgmt_preview[] PROGMEM_MARKER       = {'u', 's', 'e', 'r', 'V', 'e', 'r', 'i', 'f', 'i', 'c', 'a', 't', 'i', 'o', 'n', 'M', 'g', 'm', 't', 'P', 'r', 'e', 'v', 'i', 'e', 'w'};
static const char fido_option_uv_bio_enroll[] PROGMEM_MARKER                        = {'u', 'v', 'B', 'i', 'o', 'E', 'n', 'r', 'o', 'l', 'l'};
static const char fido_option_authnr_config[] PROGMEM_MARKER                        = {'a', 'u', 't', 'h', 'n', 'r', 'C', 'f', 'g'};
static const char fido_option_uv_acfg[] PROGMEM_MARKER                              = {'u', 'v', 'A', 'c', 'f', 'g'};
static const char fido_option_cred_mgmt[] PROGMEM_MARKER                            = {'c', 'r', 'e', 'd', 'M', 'g', 'm', 't'};
static const char fido_option_credential_management_preview[] PROGMEM_MARKER        = {'c', 'r', 'e', 'd', 'e', 'n', 't', 'i', 'a', 'l', 'M', 'g', 'm', 't', 'P', 'r', 'e', 'v', 'i', 'e', 'w'};
static const char fido_option_set_min_pin_length[] PROGMEM_MARKER                   = {'s', 'e', 't', 'M', 'i', 'n', 'P', 'I', 'N', 'L', 'e', 'n', 'g', 't', 'h'};
static const char fido_option_make_cred_uv_not_rqd[] PROGMEM_MARKER                 = {'m', 'a', 'k', 'e', 'C', 'r', 'e', 'd', 'U', 'v', 'N', 'o', 't', 'R', 'q', 'd'};
static const char fido_option_always_uv[] PROGMEM_MARKER                            = {'a', 'l', 'w', 'a', 'y', 's', 'U', 'v'};

// transports
static const char fido_transport_nfc[] PROGMEM_MARKER       = {'n', 'f', 'c'};
static const char fido_transport_usb[] PROGMEM_MARKER       = {'u', 's', 'b'};
static const char fido_transport_ble[] PROGMEM_MARKER       = {'b', 'l', 'e'};
static const char fido_transport_internal[] PROGMEM_MARKER  = {'i', 'n', 't', 'e', 'r', 'n', 'a', 'l'};

// algorithm
static const char fido_algorithm_key[] PROGMEM_MARKER  = {'a', 'l', 'g'};

/**
 * @brief Resets a CBOR info object.
 * 
 * @param ci The info to reset.
 */
void fido_cbor_info_reset(fido_cbor_info_t *ci) {
    memset(ci, 0x0, sizeof(*ci));
}

/**
 * @brief Extract the AAGUID from the CBOR response.
 * 
 * @param value The value containing the AAGUID.
 * @param ci The info to copy the ID to.
 * @return A FIDO_ERR
 */
static int copy_aaguid(const cb0r_t value, fido_cbor_info_t *ci) {
    if (!cbor_bytestring_is_definite(value) || value->length != sizeof(ci->aaguid)) {
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    }
    memcpy(ci->aaguid, value -> start + value->header, value->length);
    return FIDO_OK;
}

/**
 * @brief Decode an unsigned integer from the CBOR response.
 * 
 * @param value The value to decode.
 * @param target A pointer to a location to store the decoded value at.
 * @return int A FIDO_ERR
 */
static int decode_uint64(const cb0r_t value, uint64_t *target) {
    if (value->type != CB0R_INT) {
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    }
    *target = value->value;
    return FIDO_OK;
}

/**
 * @brief Parse the versions array from the CBOR response.
 * 
 * @param element The element in the array.
 * @param ci User-passed argument (here: CBOR info).
 * @return int FIDO_OK if versions could be parsed.
 */
static int cbor_info_decode_versions(const cb0r_t element, void *ci) {
    fido_cbor_info_t* info = (fido_cbor_info_t*) ci;

    if (!cbor_bytestring_is_definite(element)) {
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    }

    if(CBOR_STR_MEMCMP(element, fido_2_1_version)) {
        info->versions |= FIDO_VERSION_FIDO_2_1;
    } else if(CBOR_STR_MEMCMP(element, fido_2_0_version)) {
        info->versions |= FIDO_VERSION_FIDO_2_0;
    } else if(CBOR_STR_MEMCMP(element, fido_2_1_pre_version)) {
        info->versions |= FIDO_VERSION_FIDO_2_1_PRE;
    } else if(CBOR_STR_MEMCMP(element, fido_u2f_v2_version)) {
        info->versions |= FIDO_VERSION_U2F_V2;
    } else {
        return FIDO_ERR_INVALID_ARGUMENT;
    }

    return FIDO_OK;
}

/**
 * @brief Parse the extensions array from the CBOR response.
 * 
 * @param element The element in the array.
 * @param ci User-passed argument (here: CBOR info).
 * @return int FIDO_OK if extensions could be parsed.
 */
static int cbor_info_decode_extensions(const cb0r_t element, void *ci) {
    if (!cbor_bytestring_is_definite(element)) {
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    }

    fido_cbor_info_t* info = (fido_cbor_info_t*) ci;

    if(CBOR_STR_MEMCMP(element, fido_extension_cred_blob)) {
        info->versions |= FIDO_EXTENSION_CRED_BLOB;
    } else if(CBOR_STR_MEMCMP(element, fido_extension_hmac_secret)) {
        info->versions |= FIDO_EXTENSION_HMAC_SECRET;
    } else if(CBOR_STR_MEMCMP(element, fido_extension_cred_protect)) {
        info->versions |= FIDO_EXTENSION_CRED_PROTECT;
    } else if(CBOR_STR_MEMCMP(element, fido_extension_large_blob_key)) {
        info->versions |= FIDO_EXTENSION_LARGE_BLOB_KEY;
    } else if(CBOR_STR_MEMCMP(element, fido_extension_min_pin_length)) {
        info->versions |= FIDO_EXTENSION_MIN_PIN_LENGTH;
    }

    return FIDO_OK;
}

/**
 * @brief Parse the options map from the CBOR response.
 * 
 * @param key The key in the map.
 * @param value The value in the map.
 * @param ci User-passed argument (here: CBOR info).
 * @return int FIDO_OK if extensions could be parsed.
 */
static int cbor_info_decode_options(const cb0r_t key, const cb0r_t value, void *ci) {
    if (!cbor_bytestring_is_definite(key)) {
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    }

    // The options map (currently) contains either true or false
    if (value->type != CB0R_FALSE && value->type != CB0R_TRUE) {
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    }

    if (value->type == CB0R_FALSE) {
        // Nothing to do if the option is set to false, since it is not supported then.
        return FIDO_OK;
    }

    fido_cbor_info_t* info = (fido_cbor_info_t*) ci;

    if(CBOR_STR_MEMCMP(key, fido_option_plat)) {
        info->options |= FIDO_OPTION_PLAT;
    } else if(CBOR_STR_MEMCMP(key, fido_option_rk)) {
        info->options |= FIDO_OPTION_RK;
    } else if(CBOR_STR_MEMCMP(key, fido_option_client_pin)) {
        info->options |= FIDO_OPTION_CLIENT_PIN;
    } else if(CBOR_STR_MEMCMP(key, fido_option_up)) {
        info->options |= FIDO_OPTION_UP;
    } else if(CBOR_STR_MEMCMP(key, fido_option_uv)) {
        info->options |= FIDO_OPTION_UV;
    } else if(CBOR_STR_MEMCMP(key, fido_option_pin_uv_auth_token)) {
        info->options |= FIDO_OPTION_PIN_UV_AUTH_TOKEN;
    } else if(CBOR_STR_MEMCMP(key, fido_option_no_mc_ga_permissions_with_client_pin)) {
        info->options |= FIDO_OPTION_NO_MC_GA_PERMISSIONS_WITH_CLIENT_PIN;
    } else if(CBOR_STR_MEMCMP(key, fido_option_large_blobs)) {
        info->options |= FIDO_OPTION_LARGE_BLOBS;
    } else if(CBOR_STR_MEMCMP(key, fido_option_ep)) {
        info->options |= FIDO_OPTION_EP;
    } else if(CBOR_STR_MEMCMP(key, fido_option_bio_enroll)) {
        info->options |= FIDO_OPTION_BIO_ENROLL;
    } else if(CBOR_STR_MEMCMP(key, fido_option_user_verification_mgmt_preview)) {
        info->options |= FIDO_OPTION_USER_VERIFICATION_MGMT_PREVIEW;
    } else if(CBOR_STR_MEMCMP(key, fido_option_uv_bio_enroll)) {
        info->options |= FIDO_OPTION_UV_BIO_ENROLL;
    } else if(CBOR_STR_MEMCMP(key, fido_option_authnr_config)) {
        info->options |= FIDO_OPTION_AUTHNR_CONFIG;
    } else if(CBOR_STR_MEMCMP(key, fido_option_uv_acfg)) {
        info->options |= FIDO_OPTION_UV_ACFG;
    } else if(CBOR_STR_MEMCMP(key, fido_option_cred_mgmt)) {
        info->options |= FIDO_OPTION_CRED_MGMT;
    } else if(CBOR_STR_MEMCMP(key, fido_option_credential_management_preview)) {
        info->options |= FIDO_OPTION_CREDENTIAL_MANAGEMENT_PREVIEW;
    } else if(CBOR_STR_MEMCMP(key, fido_option_set_min_pin_length)) {
        info->options |= FIDO_OPTION_SET_MIN_PIN_LENGTH;
    } else if(CBOR_STR_MEMCMP(key, fido_option_make_cred_uv_not_rqd)) {
        info->options |= FIDO_OPTION_MAKE_CRED_UV_NOT_RQD;
    } else if(CBOR_STR_MEMCMP(key, fido_option_always_uv)) {
        info->options |= FIDO_OPTION_ALWAYS_UV;
    }

    return FIDO_OK;
}

/**
 * @brief Parse a cb0r element containing a PIN Protocol
 * 
 * @param element The cb0r element containing the byte representing the protocol
 * @param arg The cb0r_info_t
 * @return int FIDO_OK if extensions could be parsed.
 */
static int cbor_info_decode_protocol(const cb0r_t element, void *arg) {
    fido_cbor_info_t *ci = (fido_cbor_info_t*)arg;

    if(element->type != CB0R_INT) {
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    }
    switch ((uint8_t)element->value) {
        case 1:
            ci->protocols |= FIDO_PIN_PROTOCOL_1;
            break;
        case 2:
            ci->protocols |= FIDO_PIN_PROTOCOL_2;
            break;
        default:
            // Just ignore.
            break;
    }
    return FIDO_OK;
}


static int cbor_info_decode_transport(const cb0r_t element, void *arg) {
    fido_cbor_info_t *ci = (fido_cbor_info_t*)ci;
    if(CBOR_STR_MEMCMP(element, fido_transport_usb)) {
        ci->transports |= FIDO_TRANSPORT_USB;
    } else if(CBOR_STR_MEMCMP(element, fido_transport_nfc)) {
        ci->versions |= FIDO_TRANSPORT_NFC;
    } else if(CBOR_STR_MEMCMP(element, fido_transport_ble)) {
        ci->versions |= FIDO_TRANSPORT_BLE;
    } else if(CBOR_STR_MEMCMP(element, fido_transport_internal)) {
        ci->versions |= FIDO_TRANSPORT_INTERNAL;
    } else {
        return FIDO_ERR_INVALID_ARGUMENT;
    }
    return FIDO_OK;
}

static int cbor_info_decode_algorithm_entry(const cb0r_t key, const cb0r_t value, void *arg) {
    fido_cbor_info_t *ci = (fido_cbor_info_t*)arg;
    if (!cbor_bytestring_is_definite(key)) {
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    }

    if (CBOR_STR_MEMCMP(key, fido_algorithm_key)) {
        if (value->type != CB0R_INT && value->type != CB0R_NEG) {
            return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
        }
        int32_t alg_identifier = value->type == CB0R_NEG ? ((~value->value) & 0xffffffff) : (value->value & 0xffffffff);
        switch (alg_identifier) {
            case COSE_ALGORITHM_EdDSA:
                ci->algorithms |= FIDO_CREDENTIAL_GENERATION_EdDSA;
                break;
            case COSE_ALGORITHM_ES256:
                ci->algorithms |= FIDO_CREDENTIAL_GENERATION_ES256;
                break;
            case COSE_ALGORITHM_ES384:
                ci->algorithms |= FIDO_CREDENTIAL_GENERATION_ES384;
                break;
            case COSE_ALGORITHM_ES512:
                ci->algorithms |= FIDO_CREDENTIAL_GENERATION_ES512;
                break;
            case COSE_ALGORITHM_ES256K:
                ci->algorithms |= FIDO_CREDENTIAL_GENERATION_ES256K;
                break;
            case COSE_ALGORITHM_PS256:
                ci->algorithms |= FIDO_CREDENTIAL_GENERATION_PS256;
                break;
            case COSE_ALGORITHM_RS256:
                ci->algorithms |= FIDO_CREDENTIAL_GENERATION_RS256;
                break;
        }
    }
    return FIDO_OK;
}

static int cbor_info_decode_algorithm(const cb0r_t element, void *arg) {
    if (element->type != CB0R_MAP) {
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    }

    return cbor_iter_map(element, cbor_info_decode_algorithm_entry, arg);
}


static int parse_info_reply_entry(const cb0r_t key, const cb0r_t value, void *arg) {
    if (key->type != CB0R_INT || key->value > UINT8_MAX) {
        // Just ignore the entry according to https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#message-encoding.
        return FIDO_OK;
    }

    fido_cbor_info_t *ci = (fido_cbor_info_t*)arg;

    switch (key->value) {
        case 1: // versions
            return cbor_iter_array(value, cbor_info_decode_versions, ci);
        case 2: // extensions
            return cbor_iter_array(value, cbor_info_decode_extensions, ci);
        case 3: // aaguid
            return copy_aaguid(value, ci);
        case 4: // options
            return cbor_iter_map(value, cbor_info_decode_options, ci);
        case 5: // maxMsgSize
            return decode_uint64(value, &ci->maxmsgsize);
        case 6: // pinProtocols
            return cbor_iter_array(value, cbor_info_decode_protocol, ci);
        case 7: // maxCredentialCountInList
            return decode_uint64(value, &ci->maxcredcntlst);
        case 8: // maxCredentialIdLength
            return decode_uint64(value, &ci->maxcredidlen);
        case 9: // transports
            return cbor_iter_array(value, cbor_info_decode_transport, ci);
        case 10: // algorithms
            return cbor_iter_array(value, cbor_info_decode_algorithm, ci);
        case 11: // maxSerializedLargeBlobArray
            return decode_uint64(value, &ci->maxlargeblob);
        case 14: // fwVersion
            return decode_uint64(value, &ci->fwversion);
        case 15: // maxCredBlobLen
            return decode_uint64(value, &ci->maxcredbloblen);
        default: // ignore
            fido_log_debug("%s: cbor type", __func__);
            return FIDO_OK;
    }
}

static int fido_dev_get_cbor_info_tx(fido_dev_t *dev) {
    const unsigned char cbor[] = { CTAP_CBOR_GETINFO };

    fido_log_debug("%s: dev=%p", __func__, (void *)dev);

    if (fido_tx(dev, CTAP_CMD_CBOR, cbor, sizeof(cbor)) < 0) {
        fido_log_debug("%s: fido_tx", __func__);
        return FIDO_ERR_TX;
    }

    return FIDO_OK;
}

static int fido_dev_get_cbor_info_rx(fido_dev_t *dev, fido_cbor_info_t *ci) {
    unsigned char   msg[FIDO_MAXMSG];
    int             msglen;

    fido_log_debug("%s: dev=%p, ci=%p, ms=%d", __func__, (void *)dev, (void *)ci, *ms);

    fido_cbor_info_reset(ci);

    if ((msglen = fido_rx(dev, CTAP_CMD_CBOR, msg, sizeof(msg))) < 0) {
        fido_log_debug("%s: fido_rx", __func__);
        return FIDO_ERR_RX;
    }

    if (msg[0] != FIDO_ERR_SUCCESS) {
        return msg[0];
    }

    cb0r_s map;
    // This should always be a map.
    if (!cb0r_read(msg+1, msglen-1, &map) || map.type != CB0R_MAP) {
        return  FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    }

    // The next step parses the response.
    return cbor_iter_map(&map, &parse_info_reply_entry, ci);
}

int fido_dev_get_cbor_info_wait(fido_dev_t *dev, fido_cbor_info_t *ci) {
    int r;

    if ((r = fido_dev_get_cbor_info_tx(dev)) != FIDO_OK ||
        (r = fido_dev_get_cbor_info_rx(dev, ci)) != FIDO_OK) {
        return (r);
    }

    return FIDO_OK;
}
