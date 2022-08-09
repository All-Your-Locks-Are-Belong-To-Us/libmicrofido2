/*
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include "fido.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void *example_open() {
    printf("open\n");
    return (void*)1; // Just return a fake handle for this device.
};

static void example_close(void *handle) {
    printf("close\n");
}

enum fido_state {
    FIDO_STATE_UNINIT = 0,
    FIDO_STATE_APPLET_SELECTION,
    FIDO_STATE_GET_INFO,
    FIDO_STATE_GET_LARGE_BLOB,
    FIDO_STATE_GET_ASSERTION,
};

static enum fido_state sim_state = FIDO_STATE_UNINIT;
static size_t read_offset = 0;

static int example_read(void *handle, unsigned char *buf, const size_t len) {
    printf("trying to read %zu bytes\n", len);
    const uint8_t *copy_pointer = NULL;
    size_t copy_len = 0;
    switch (sim_state)
    {
        case FIDO_STATE_APPLET_SELECTION:
            {
                static const uint8_t app_select_response[] = "U2F_V2";
                static const size_t version_length = sizeof(app_select_response) - 1;
                copy_pointer = app_select_response;
                copy_len = version_length;
                break;
            }
        case FIDO_STATE_GET_INFO:
            {
                // Send get info response.
                // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo
                static const uint8_t get_info_response[] = {
                    FIDO_OK,
                    // {1: ["FIDO_2_1"], 2: ["largeBlobKey"], 3: h'30313233343536373839303132333435', 4: {"largeBlobs": true}, 5: 2048, 9: ["nfc"], 11: 1024}
                    0xA7, 0x01, 0x81, 0x68, 0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x31, 0x02, 0x81, 0x6C, 0x6C, 0x61, 0x72, 0x67, 0x65, 0x42, 0x6C, 0x6F, 0x62, 0x4B, 0x65, 0x79, 0x03, 0x50, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x04, 0xA1, 0x6A, 0x6C, 0x61, 0x72, 0x67, 0x65, 0x42, 0x6C, 0x6F, 0x62, 0x73, 0xF5, 0x05, 0x19, 0x08, 0x00, 0x09, 0x81, 0x63, 0x6E, 0x66, 0x63, 0x0B, 0x19, 0x04, 0x00,
                };
                copy_pointer = get_info_response;
                copy_len = sizeof(get_info_response);
                break;
            }
        case FIDO_STATE_GET_LARGE_BLOB:
            {
                // plaintext: kitten
                // key: 0xCA, 0x97, 0x81, 0x12, 0xCA, 0x1B, 0xBD, 0xCA, 0xFA, 0xC2, 0x31, 0xB3, 0x9A, 0x23, 0xDC, 0x4D, 0xA7, 0x86, 0xEF, 0xF8, 0x14, 0x7C, 0x4E, 0x72, 0xB9, 0x80, 0x77, 0x85, 0xAF, 0xEE, 0x48, 0xBB
                // [{1: h'53cbebb35d0cf479372a10a94892d8bbfc47a67257cb22958ad655455efb98cd', 2: h'33582CB89E78D63967801A77', 3: 6}]
                static const uint8_t get_large_blob_response[] = {
                    FIDO_OK,
                    // {1: h'81A301582053CBEBB35D0CF479372A10A94892D8BBFC47A67257CB22958AD655455EFB98CD024C33582CB89E78D63967801A7703060b66d4ae669185b3f4722c5f576e172d'}
                    0xA1, 0x01, 0x58, 0x45, 0x81, 0xA3, 0x01, 0x58, 0x20, 0x53, 0xCB, 0xEB, 0xB3, 0x5D, 0x0C, 0xF4, 0x79, 0x37, 0x2A, 0x10, 0xA9, 0x48, 0x92, 0xD8, 0xBB, 0xFC, 0x47, 0xA6, 0x72, 0x57, 0xCB, 0x22, 0x95, 0x8A, 0xD6, 0x55, 0x45, 0x5E, 0xFB, 0x98, 0xCD, 0x02, 0x4C, 0x33, 0x58, 0x2C, 0xB8, 0x9E, 0x78, 0xD6, 0x39, 0x67, 0x80, 0x1A, 0x77, 0x03, 0x06, 0x0B, 0x66, 0xD4, 0xAE, 0x66, 0x91, 0x85, 0xB3, 0xF4, 0x72, 0x2C, 0x5F, 0x57, 0x6E, 0x17, 0x2D,
                    // from Chromium.
                    // 0xA1, 0x01, 0x58, 0xAC, 0x81, 0xA3, 0x01, 0x58, 0x86, 0x7D, 0xB9, 0x8C, 0x5B, 0x62, 0xC6, 0x84, 0x4A, 0x89, 0xAC, 0x92, 0x87, 0x25, 0x32, 0xE0, 0x09, 0xCF, 0xD6, 0xFB, 0x86, 0x5A, 0xB8, 0x36, 0xF3, 0xD2, 0x46, 0xC7, 0xBD, 0x98, 0x69, 0x9C, 0x9B, 0x6F, 0x42, 0x2F, 0x25, 0xB0, 0x29, 0xCC, 0x6B, 0xAF, 0xB0, 0xE8, 0x33, 0xB4, 0x5F, 0xF7, 0x96, 0x33, 0x3D, 0xED, 0x38, 0x59, 0x95, 0x2F, 0x8B, 0x02, 0x9C, 0x03, 0x09, 0xC9, 0xAE, 0x75, 0xAC, 0x37, 0xC8, 0xB4, 0x70, 0x5D, 0xBB, 0x9D, 0x7D, 0x75, 0xE4, 0x90, 0x50, 0x71, 0xF2, 0x43, 0x7E, 0x77, 0x4C, 0xD6, 0xE1, 0xC1, 0xBA, 0xE2, 0x69, 0x95, 0x23, 0x72, 0xC9, 0x8E, 0xEE, 0xB7, 0x51, 0xED, 0xB5, 0xB0, 0x25, 0x00, 0x81, 0x18, 0xAA, 0xD4, 0xAF, 0x59, 0xC6, 0xF4, 0x8E, 0x84, 0x63, 0x91, 0x97, 0x6F, 0x10, 0xF8, 0xF6, 0x92, 0x34, 0x15, 0x1E, 0x34, 0x52, 0xD4, 0x2A, 0x9E, 0xCA, 0x96, 0x9C, 0x34, 0x5F, 0x68, 0x95, 0x02, 0x4C, 0x6A, 0x26, 0x7B, 0x79, 0x97, 0xBE, 0x23, 0x44, 0x60, 0x33, 0x65, 0xA1, 0x03, 0x18, 0x71, 0x46, 0x86, 0x64, 0x52, 0x87, 0xB8, 0x0B, 0x74, 0x11, 0xEA, 0x56, 0x19, 0xB9, 0xD2, 0x96, 0xDD,
                };
                copy_pointer = get_large_blob_response;
                copy_len = sizeof(get_large_blob_response);
                break;
            }
        case FIDO_STATE_GET_ASSERTION:
            {
                // RPID: wau.felixgohla.de
                // credential id: A30058B6D6BB6F08D40953DA8B8C68EF61BD5C0FD69AF7E33E14E549FA34F817713BF00F938B64E8BCF65FAA4AF46FFB58C540CFDC992CC29C10FF5366575FE2806F97216A0D548A5372299EAAA642356E1A35DAC6BA60E31C0A7011B1471435E5A5E9E9DA2B5533AF93C4DF9C6438D5E5231BBAA98009D20DBC976350408E3866F1CE79CAAD58E2FF1845A3122938702EE295E9C3F564D6505C094493D9CCEADB01EECE6348C7981BF3AC54E0C35DFAAFE98D6B8639474E9528014C4A3867D15064ED2976EE16A70250DF74DF81C00014BEA89467E2073154D0
                // signature count: 5
                // so authdata hex is: 50569158BE61D7A1BA084F80E45E938FD326E0A8DFF07B37036E6C82303AE26B0000000005
                // expected client data hash: 039058C6F2C0CB492C533B0A4D14EF77CC0F78ABCCCED5287D84A1A2011CFB81
                // preimage (authdata + cdh): 50569158BE61D7A1BA084F80E45E938FD326E0A8DFF07B37036E6C82303AE26B0000000005039058C6F2C0CB492C533B0A4D14EF77CC0F78ABCCCED5287D84A1A2011CFB81
                // signature: FF08AB2BD13DCAFCD9FBE0004C14FEA5D7A0D06F198A531DDE6BDF4B55086BC80EC7FC4DFF4B2959F7957B15A9B86099E3DCE6F47559FF751C0ACE902E88E004
                //
                // Python script to verify signature:
                // from cryptography.hazmat.primitives.asymmetric import ed25519
                // public_key_bytes = bytes.fromhex("C8B0CCF2BD4CB1ABEAE0F6C4C9A7A315BB7A1F6F9E98F5DA6A727E38C9F145A8")
                // loaded_public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
                // authdata = bytes.fromhex("50569158BE61D7A1BA084F80E45E938FD326E0A8DFF07B37036E6C82303AE26B0000000005")
                // client_data_hash = bytes.fromhex("039058C6F2C0CB492C533B0A4D14EF77CC0F78ABCCCED5287D84A1A2011CFB81")
                // preimage = authdata + client_data_hash
                // signature = bytes.fromhex("FF08AB2BD13DCAFCD9FBE0004C14FEA5D7A0D06F198A531DDE6BDF4B55086BC80EC7FC4DFF4B2959F7957B15A9B86099E3DCE6F47559FF751C0ACE902E88E004")
                // loaded_public_key.verify(signature, preimage)
                //
                // Python script to sign stuff:
                // from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                // from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
                // private_key = Ed25519PrivateKey.generate()
                // print('private key:', private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex())
                // signature = private_key.sign(b"blub")
                // public_key = private_key.public_key()
                // print('public key: ', public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex())
                // print('signature:', signature.hex())
                //
                // generated private key: 073fc2b58607166290f3e7eaec08d09422a28ce0df26c229674220add2372703
                // thus public key is: 63afd18bf452923564f557c77726d63b730ccca29dabf392bfd52bb5d25e9f60
                //
                // complete cbor: {1: {"id": h'A30058B6D6BB6F08D40953DA8B8C68EF61BD5C0FD69AF7E33E14E549FA34F817713BF00F938B64E8BCF65FAA4AF46FFB58C540CFDC992CC29C10FF5366575FE2806F97216A0D548A5372299EAAA642356E1A35DAC6BA60E31C0A7011B1471435E5A5E9E9DA2B5533AF93C4DF9C6438D5E5231BBAA98009D20DBC976350408E3866F1CE79CAAD58E2FF1845A3122938702EE295E9C3F564D6505C094493D9CCEADB01EECE6348C7981BF3AC54E0C35DFAAFE98D6B8639474E9528014C4A3867D15064ED2976EE16A70250DF74DF81C00014BEA89467E2073154D0', "type": "public-key"}, 2: h'50569158BE61D7A1BA084F80E45E938FD326E0A8DFF07B37036E6C82303AE26B0000000005', 3: h'FF08AB2BD13DCAFCD9FBE0004C14FEA5D7A0D06F198A531DDE6BDF4B55086BC80EC7FC4DFF4B2959F7957B15A9B86099E3DCE6F47559FF751C0ACE902E88E004', 4: {"id": h'34313937613430662D393263662D343366622D393438352D323630343163666663633636'}}
                static const uint8_t get_assertion_response[] = {
                    FIDO_OK,
                    0xa4, 0x01, 0xa2, 0x62, 0x69, 0x64, 0x58, 0xda, 0xa3, 0x00, 0x58, 0xb6, 0xd6, 0xbb, 0x6f,0x08, 0xd4, 0x09, 0x53, 0xda, 0x8b, 0x8c, 0x68, 0xef, 0x61, 0xbd, 0x5c, 0x0f, 0xd6, 0x9a, 0xf7,0xe3, 0x3e, 0x14, 0xe5, 0x49, 0xfa, 0x34, 0xf8, 0x17, 0x71, 0x3b, 0xf0, 0x0f, 0x93, 0x8b, 0x64,0xe8, 0xbc, 0xf6, 0x5f, 0xaa, 0x4a, 0xf4, 0x6f, 0xfb, 0x58, 0xc5, 0x40, 0xcf, 0xdc, 0x99, 0x2c,0xc2, 0x9c, 0x10, 0xff, 0x53, 0x66, 0x57, 0x5f, 0xe2, 0x80, 0x6f, 0x97, 0x21, 0x6a, 0x0d, 0x54,0x8a, 0x53, 0x72, 0x29, 0x9e, 0xaa, 0xa6, 0x42, 0x35, 0x6e, 0x1a, 0x35, 0xda, 0xc6, 0xba, 0x60,0xe3, 0x1c, 0x0a, 0x70, 0x11, 0xb1, 0x47, 0x14, 0x35, 0xe5, 0xa5, 0xe9, 0xe9, 0xda, 0x2b, 0x55,0x33, 0xaf, 0x93, 0xc4, 0xdf, 0x9c, 0x64, 0x38, 0xd5, 0xe5, 0x23, 0x1b, 0xba, 0xa9, 0x80, 0x09,0xd2, 0x0d, 0xbc, 0x97, 0x63, 0x50, 0x40, 0x8e, 0x38, 0x66, 0xf1, 0xce, 0x79, 0xca, 0xad, 0x58,0xe2, 0xff, 0x18, 0x45, 0xa3, 0x12, 0x29, 0x38, 0x70, 0x2e, 0xe2, 0x95, 0xe9, 0xc3, 0xf5, 0x64,0xd6, 0x50, 0x5c, 0x09, 0x44, 0x93, 0xd9, 0xcc, 0xea, 0xdb, 0x01, 0xee, 0xce, 0x63, 0x48, 0xc7,0x98, 0x1b, 0xf3, 0xac, 0x54, 0xe0, 0xc3, 0x5d, 0xfa, 0xaf, 0xe9, 0x8d, 0x6b, 0x86, 0x39, 0x47,0x4e, 0x95, 0x28, 0x01, 0x4c, 0x4a, 0x38, 0x67, 0xd1, 0x50, 0x64, 0xed, 0x29, 0x76, 0xee, 0x16,0xa7, 0x02, 0x50, 0xdf, 0x74, 0xdf, 0x81, 0xc0, 0x00, 0x14, 0xbe, 0xa8, 0x94, 0x67, 0xe2, 0x07,0x31, 0x54, 0xd0, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d,0x6b, 0x65, 0x79, 0x02, 0x58, 0x25, 0x50, 0x56, 0x91, 0x58, 0xbe, 0x61, 0xd7, 0xa1, 0xba, 0x08,0x4f, 0x80, 0xe4, 0x5e, 0x93, 0x8f, 0xd3, 0x26, 0xe0, 0xa8, 0xdf, 0xf0, 0x7b, 0x37, 0x03, 0x6e,0x6c, 0x82, 0x30, 0x3a, 0xe2, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x05, 0x03, 0x58, 0x40, 0xff, 0x08,0xab, 0x2b, 0xd1, 0x3d, 0xca, 0xfc, 0xd9, 0xfb, 0xe0, 0x00, 0x4c, 0x14, 0xfe, 0xa5, 0xd7, 0xa0,0xd0, 0x6f, 0x19, 0x8a, 0x53, 0x1d, 0xde, 0x6b, 0xdf, 0x4b, 0x55, 0x08, 0x6b, 0xc8, 0x0e, 0xc7,0xfc, 0x4d, 0xff, 0x4b, 0x29, 0x59, 0xf7, 0x95, 0x7b, 0x15, 0xa9, 0xb8, 0x60, 0x99, 0xe3, 0xdc,0xe6, 0xf4, 0x75, 0x59, 0xff, 0x75, 0x1c, 0x0a, 0xce, 0x90, 0x2e, 0x88, 0xe0, 0x04, 0x04, 0xa1,0x62, 0x69, 0x64, 0x58, 0x24, 0x34, 0x31, 0x39, 0x37, 0x61, 0x34, 0x30, 0x66, 0x2d, 0x39, 0x32,0x63, 0x66, 0x2d, 0x34, 0x33, 0x66, 0x62, 0x2d, 0x39, 0x34, 0x38, 0x35, 0x2d, 0x32, 0x36, 0x30,0x34, 0x31, 0x63, 0x66, 0x66, 0x63, 0x63, 0x36, 0x36
                    };
                copy_pointer = get_assertion_response;
                copy_len = sizeof(get_assertion_response);
                break;
            }
    case FIDO_STATE_UNINIT:
    default:
        return 0;
    }

    assert(copy_len > 0);
    assert(copy_pointer != NULL);

    size_t bytes_returned = 0;
    size_t rest_bytes = copy_len - read_offset;

    if (rest_bytes >= len - 2 /* 2 bytes status */) {
        printf("Message of len %ld too large, need to read again!\n", rest_bytes);
        memcpy(buf, copy_pointer + read_offset, len - 2);
        read_offset += len - 2;
        bytes_returned = len;
        rest_bytes -= bytes_returned;
        buf[len - 2] = 0x61; // more data
        buf[len - 1] = rest_bytes > 0xff ? 0xff : rest_bytes; // those many bytes still available
        printf("reading: ");
        for (size_t i = 0; i < len; ++i) {
            printf("%02x ", buf[i]);
        }
        putc('\n', stdout);
    } else {
        memcpy(buf, copy_pointer + read_offset, rest_bytes);
        buf[rest_bytes] = 0x90;
        buf[rest_bytes + 1] = 0x00;
        bytes_returned = rest_bytes + 2;
        printf("reading: ");
        for (size_t i = 0; i < rest_bytes + 2; ++i) {
            printf("%02x ", buf[i]);
        }
        putc('\n', stdout);
    }
    return bytes_returned;
}

#define NFC_GET_RESPONSE 0xc0

static int example_write(void *handle, const unsigned char *buf, const size_t len) {
    // Output the buffer.
    printf("writing: ");
    for (size_t i = 0; i < len; ++i) {
        printf("%02x ", buf[i]);
    }
    putc('\n', stdout);

    if (buf[1] == NFC_GET_RESPONSE) {
        // Just continue with previous reading.
        printf("Trying continue to read next %d bytes.\n", buf[4]);
        return (int)len;
    }

    // Stupid state machine, that does not know anything about parsing the message completely.
    switch (sim_state) {
        case FIDO_STATE_UNINIT:
            sim_state = FIDO_STATE_APPLET_SELECTION;
            break;
        case FIDO_STATE_APPLET_SELECTION:
            sim_state = FIDO_STATE_GET_INFO;
            break;
        case FIDO_STATE_GET_INFO:
            sim_state = FIDO_STATE_GET_LARGE_BLOB;
            break;
        case FIDO_STATE_GET_LARGE_BLOB:
            sim_state = FIDO_STATE_GET_ASSERTION;
            break;
        default: break;
    }
    read_offset = 0;
    return (int)len;
}

static const fido_dev_io_t nfc_io = {
    .open = example_open,
    .close = example_close,
    .read = example_read,
    .write = example_write
};

int main(void) {
    fido_dev_t dev;
    if (fido_init_nfc_device(&dev, &nfc_io) != FIDO_OK) {
        return 1;
    }

    if (fido_dev_open(&dev) != FIDO_OK) {
        return 2;
    }

    {
        // Retrieve large blob.
        uint8_t key[] = {
            0xCA, 0x97, 0x81, 0x12, 0xCA, 0x1B, 0xBD, 0xCA, 0xFA, 0xC2, 0x31, 0xB3, 0x9A, 0x23, 0xDC, 0x4D, 0xA7, 0x86, 0xEF, 0xF8, 0x14, 0x7C, 0x4E, 0x72, 0xB9, 0x80, 0x77, 0x85, 0xAF, 0xEE, 0x48, 0xBB,
            // from Chromium
            // 0xF7, 0x8E, 0x65, 0x59, 0xF4, 0xE8, 0x70, 0xF2, 0xF0, 0x37, 0x41, 0x63, 0x85, 0x31, 0xEF, 0x31, 0x50, 0x8F, 0x76, 0x18, 0x73, 0x4B, 0x68, 0x7A, 0x4A, 0x42, 0x16, 0x65, 0xEA, 0x6A, 0x7F, 0xA2,
        };
        fido_blob_t blob;
        uint8_t outbuf[2048] = {0};
        fido_blob_reset(&blob, outbuf, sizeof(outbuf));
        if (fido_dev_largeblob_get(&dev, key, sizeof(key), &blob) != FIDO_OK) {
            return 3;
        }
    }

    // Assertion.
    {
        const uint8_t client_data_hash[] = {
            0x03, 0x90, 0x58, 0xC6, 0xF2, 0xC0, 0xCB, 0x49, 0x2C, 0x53, 0x3B, 0x0A, 0x4D, 0x14, 0xEF, 0x77, 0xCC, 0x0F, 0x78, 0xAB, 0xCC, 0xCE, 0xD5, 0x28, 0x7D, 0x84, 0xA1, 0xA2, 0x01, 0x1C, 0xFB, 0x81,
        };
        const uint8_t pubkey[] = {
            0xC8, 0xB0, 0xCC, 0xF2, 0xBD, 0x4C, 0xB1, 0xAB, 0xEA, 0xE0, 0xF6, 0xC4, 0xC9, 0xA7, 0xA3, 0x15, 0xBB, 0x7A, 0x1F, 0x6F, 0x9E, 0x98, 0xF5, 0xDA, 0x6A, 0x72, 0x7E, 0x38, 0xC9, 0xF1, 0x45, 0xA8,
            };
        fido_assert_t assertion;
        fido_assert_reset(&assertion);
        fido_assert_set_client_data_hash(&assertion, client_data_hash);
        fido_assert_set_rp(&assertion, "wau.felixgohla.de");
        //fido_assert_set_options(&assertion, FIDO_ASSERT_OPTION_UP);
        //fido_assert_set_extensions(&assertion, FIDO_ASSERT_EXTENSION_LARGE_BLOB_KEY);
        if (fido_dev_get_assert(&dev, &assertion) != FIDO_OK) {
            return 4;
        }
        int ret;
        if ((ret = fido_assert_verify(&assertion, COSE_ALGORITHM_EdDSA, pubkey)) != FIDO_OK) {
            printf("%d\n", ret);
            return 5;
        }
    }

    if (fido_dev_close(&dev) != FIDO_OK) {
        return 7;
    }

    return 0;
}
