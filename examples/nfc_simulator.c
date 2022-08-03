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

static void *mock_open() {
    printf("open\n");
    return (void*)1; // Just return a fake handle for this device.
};

static void mock_close(void *handle) {
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

static int mock_read(void *handle, unsigned char *buf, const size_t len) {
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
                    /*
                    {
                        1: ["FIDO_2_1"],
                        2: ["largeBlobKey"],
                        3: h'30313233343536373839303132333435',
                        4: {"largeBlobs": true},
                        5: 2048,
                        9: ["nfc"],
                        11: 1024
                    }
                     */
                    0xA7, 0x01, 0x81, 0x68, 0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x31, 0x02, 0x81, 0x6C, 0x6C, 0x61, 0x72, 0x67, 0x65, 0x42, 0x6C, 0x6F, 0x62, 0x4B, 0x65, 0x79, 0x03, 0x50, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x04, 0xA1, 0x6A, 0x6C, 0x61, 0x72, 0x67, 0x65, 0x42, 0x6C, 0x6F, 0x62, 0x73, 0xF5, 0x05, 0x19, 0x08, 0x00, 0x09, 0x81, 0x63, 0x6E, 0x66, 0x63, 0x0B, 0x19, 0x04, 0x00,
                };
                copy_pointer = get_info_response;
                copy_len = sizeof(get_info_response);
                break;
            }
        case FIDO_STATE_GET_LARGE_BLOB:
            {
                /* plaintext = credential public key (32) | sign(credential public key, updater private key) (64)
                 * plaintext: 5AED41A105274508E24A11827FA9054E4E330EC40F82868D122EC7F0A9D80D04EB9B093245D9E76102F67103B9DDE76C79D1803AF60D39230954C3BF627BC8F284E2CFFC8E33CEB6D958F290A70A2F8F6A4FB0CB761EF4BA14AB771ED908A202
                 * key: 59454c4c4f57205355424d4152494e4559454c4c4f57205355424d4152494e45
                 * iv: 1800788e6a01f9ca493d40b9
                 * ciphertext: d23d47fe7fa834f11edd1bd0f8ec2d70937bfa8089d97b9dbca7f389770e793cdb3a6932ac629243ab048284e56c6ec7d688cf39518188b7b5ba1650f0b1ede1983683f6f1a95995a16425038f1b5cc01d78b111100daee82c6961060000094b17762570a3
                 * tag: 28e31509a387b77ee87fee5af7e841d9
                 * updater private key: a8ee4d2bd5ae090abca98a066ca5b3a6228489f59e3090876562b9798ae70515
                 * updater public key: fe38c2fd0b68c6f70ac333c39d282d263f833a4808901a46ee0ee7e8e0c12d77
                 */
                static const uint8_t get_large_blob_response[] = {
                    FIDO_OK,
                    /*
                    {
                        1: h'81A3015875D23D47FE7FA834F11EDD1BD0F8EC2D70937BFA8089D97B9DBCA7F389770E793CDB3A6932AC629243AB048284E56C6EC7D688CF39518188B7B5BA1650F0B1EDE1983683F6F1A95995A16425038F1B5CC01D78B111100DAEE82C6961060000094B17762570A328E31509A387B77EE87FEE5AF7E841D9024C1800788E6A01F9CA493D40B90318605bbf3b0e2479184eb3761cfbbe44aa07'
                    }

                    The value of for the entry with key 1 is the cbor-encoded version of:
                    [
                        {
                            1: h'd23d47fe7fa834f11edd1bd0f8ec2d70937bfa8089d97b9dbca7f389770e793cdb3a6932ac629243ab048284e56c6ec7d688cf39518188b7b5ba1650f0b1ede1983683f6f1a95995a16425038f1b5cc01d78b111100daee82c6961060000094b17762570a328e31509a387b77ee87fee5af7e841d9',
                            2: h'1800788e6a01f9ca493d40b9',
                            3: 96
                        }
                    ]
                    */
                    0xA1, 0x01, 0x58, 0x9B,
                    0x81, 0xA3, 0x01, 0x58, 0x75, 0xD2, 0x3D, 0x47, 0xFE, 0x7F, 0xA8, 0x34, 0xF1, 0x1E, 0xDD, 0x1B, 0xD0, 0xF8, 0xEC, 0x2D, 0x70, 0x93, 0x7B, 0xFA, 0x80, 0x89, 0xD9, 0x7B, 0x9D, 0xBC, 0xA7, 0xF3, 0x89, 0x77, 0x0E, 0x79, 0x3C, 0xDB, 0x3A, 0x69, 0x32, 0xAC, 0x62, 0x92, 0x43, 0xAB, 0x04, 0x82, 0x84, 0xE5, 0x6C, 0x6E, 0xC7, 0xD6, 0x88, 0xCF, 0x39, 0x51, 0x81, 0x88, 0xB7, 0xB5, 0xBA, 0x16, 0x50, 0xF0, 0xB1, 0xED, 0xE1, 0x98, 0x36, 0x83, 0xF6, 0xF1, 0xA9, 0x59, 0x95, 0xA1, 0x64, 0x25, 0x03, 0x8F, 0x1B, 0x5C, 0xC0, 0x1D, 0x78, 0xB1, 0x11, 0x10, 0x0D, 0xAE, 0xE8, 0x2C, 0x69, 0x61, 0x06, 0x00, 0x00, 0x09, 0x4B, 0x17, 0x76, 0x25, 0x70, 0xA3, 0x28, 0xE3, 0x15, 0x09, 0xA3, 0x87, 0xB7, 0x7E, 0xE8, 0x7F, 0xEE, 0x5A, 0xF7, 0xE8, 0x41, 0xD9, 0x02, 0x4C, 0x18, 0x00, 0x78, 0x8E, 0x6A, 0x01, 0xF9, 0xCA, 0x49, 0x3D, 0x40, 0xB9, 0x03, 0x18, 0x60, 0x5B, 0xBF, 0x3B, 0x0E, 0x24, 0x79, 0x18, 0x4E, 0xB3, 0x76, 0x1C, 0xFB, 0xBE, 0x44, 0xAA, 0x07,
                    0x90, 0x00,
                };
                copy_pointer = get_large_blob_response;
                copy_len = sizeof(get_large_blob_response);
                break;
            }
        case FIDO_STATE_GET_ASSERTION:
            {
                /*
                 * RPID: example.com
                 * auth data: a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce19470100000042
                 *     signature count: 42
                 * client data hash: 2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
                 * signed over data (auth data + client data hash): a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce194701000000422a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
                 * signature: c19f47bca338a717b1417d220bf382f0b9202eb26396a8a4df278047a6cd10fe52dfcfd4a4dbc6ca364c805bc820e0e285f3dd036d59522f32bf2b63a3c87f05
                 * credential public key: 5aed41a105274508e24a11827fa9054e4e330ec40f82868d122ec7f0a9d80d04
                 * credential private key: 382ab5f566242a455d17d4e777bd6ed5e064cf616af392fbb1f94056b9f1f05d
                 * Used https://cyphr.me/ed25519_applet/ed.html to generate and verify signatures.
                 */
                static const uint8_t get_assertion_response[] = {
                    FIDO_OK,
                    /*
                    {
                        1: {
                            "type": "public-key",
                            "id": h'a9d55f830fedd3aeb44be2a25eb8afbd2fe041abc45240145d14ea28be1ab2ea',
                            "transports": ["nfc"]},
                        2: h'a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce19470100000042',
                        3: h'C19F47BCA338A717B1417D220BF382F0B9202EB26396A8A4DF278047A6CD10FE52DFCFD4A4DBC6CA364C805BC820E0E285F3DD036D59522F32BF2B63A3C87F05',
                        4: {"id": h'416c696365'},
                        7: h'59454c4c4f57205355424d4152494e4559454c4c4f57205355424d4152494e45'
                    }
                    */
                    0xA5, 0x01, 0xA3, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6A, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0x2D, 0x6B, 0x65, 0x79, 0x62, 0x69, 0x64, 0x58, 0x20, 0xA9, 0xD5, 0x5F, 0x83, 0x0F, 0xED, 0xD3, 0xAE, 0xB4, 0x4B, 0xE2, 0xA2, 0x5E, 0xB8, 0xAF, 0xBD, 0x2F, 0xE0, 0x41, 0xAB, 0xC4, 0x52, 0x40, 0x14, 0x5D, 0x14, 0xEA, 0x28, 0xBE, 0x1A, 0xB2, 0xEA, 0x6A, 0x74, 0x72, 0x61, 0x6E, 0x73, 0x70, 0x6F, 0x72, 0x74, 0x73, 0x81, 0x63, 0x6E, 0x66, 0x63, 0x02, 0x58, 0x25, 0xA3, 0x79, 0xA6, 0xF6, 0xEE, 0xAF, 0xB9, 0xA5, 0x5E, 0x37, 0x8C, 0x11, 0x80, 0x34, 0xE2, 0x75, 0x1E, 0x68, 0x2F, 0xAB, 0x9F, 0x2D, 0x30, 0xAB, 0x13, 0xD2, 0x12, 0x55, 0x86, 0xCE, 0x19, 0x47, 0x01, 0x00, 0x00, 0x00, 0x42, 0x03, 0x58, 0x40, 0xC1, 0x9F, 0x47, 0xBC, 0xA3, 0x38, 0xA7, 0x17, 0xB1, 0x41, 0x7D, 0x22, 0x0B, 0xF3, 0x82, 0xF0, 0xB9, 0x20, 0x2E, 0xB2, 0x63, 0x96, 0xA8, 0xA4, 0xDF, 0x27, 0x80, 0x47, 0xA6, 0xCD, 0x10, 0xFE, 0x52, 0xDF, 0xCF, 0xD4, 0xA4, 0xDB, 0xC6, 0xCA, 0x36, 0x4C, 0x80, 0x5B, 0xC8, 0x20, 0xE0, 0xE2, 0x85, 0xF3, 0xDD, 0x03, 0x6D, 0x59, 0x52, 0x2F, 0x32, 0xBF, 0x2B, 0x63, 0xA3, 0xC8, 0x7F, 0x05, 0x04, 0xA1, 0x62, 0x69, 0x64, 0x45, 0x41, 0x6C, 0x69, 0x63, 0x65, 0x07, 0x58, 0x20, 0x59, 0x45, 0x4C, 0x4C, 0x4F, 0x57, 0x20, 0x53, 0x55, 0x42, 0x4D, 0x41, 0x52, 0x49, 0x4E, 0x45, 0x59, 0x45, 0x4C, 0x4C, 0x4F, 0x57, 0x20, 0x53, 0x55, 0x42, 0x4D, 0x41, 0x52, 0x49, 0x4E, 0x45,
                    0x90, 0x00,
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
        buf[len - 2] = 0x61; // more data
        buf[len - 1] = rest_bytes > 0xff ? 0xff : rest_bytes; // those many bytes still available
        printf("reading: ");
        for (size_t i = 0; i < len; ++i) {
            printf("%02x ", buf[i]);
        }
        putc('\n', stdout);
        bytes_returned = len;
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

static int mock_write(void *handle, const unsigned char *buf, const size_t len) {
    // Output the buffer.
    printf("writing: ");
    for (size_t i = 0; i < len; ++i) {
        printf("%02x ", buf[i]);
    }
    putc('\n', stdout);

    if (buf[1] == NFC_GET_RESPONSE) {
        // Just continue with previous reading.
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
            sim_state = FIDO_STATE_GET_ASSERTION;
            break;
        case FIDO_STATE_GET_ASSERTION:
            sim_state = FIDO_STATE_GET_LARGE_BLOB;
            break;
        default: break;
    }
    read_offset = 0;
    return (int)len;
}

static const fido_dev_io_t mock_nfc_io = {
    .open = mock_open,
    .close = mock_close,
    .read = mock_read,
    .write = mock_write
};

int main(void) {
    fido_dev_t dev;

    // Initialize device with mock io handlers.
    if (fido_init_nfc_device(&dev, &mock_nfc_io) != FIDO_OK) {
        return 1;
    }

    // Open the device. This also gets the device info.
    if (fido_dev_open(&dev) != FIDO_OK) {
        return 2;
    }

    // Prepare assertion.
    fido_assert_t assert;
    fido_assert_reset(&assert);
    const char *rpid = "example.com";
    uint8_t client_data_hash[ASSERTION_CLIENT_DATA_HASH_LEN];
    memset(client_data_hash, 42, sizeof(client_data_hash));
    fido_assert_set_rp(&assert, rpid);
    fido_assert_set_extensions(&assert, FIDO_ASSERT_EXTENSION_LARGE_BLOB_KEY);
    fido_assert_set_client_data_hash(&assert, client_data_hash);

    // Perform assertion. It is not verified yet, as this credential public key is unknown at this point in time.
    if (fido_dev_get_assert(&dev, &assert) != FIDO_OK) {
        return 3;
    } else if (!assert.reply.has_large_blob_key) {
        return 4;
    }

    // Read the per-credential large blob for this credential.
    fido_blob_t blob;
    uint8_t blob_buffer[1024] = {0};
    fido_blob_reset(&blob, blob_buffer, sizeof(blob_buffer));
    if (fido_dev_largeblob_get(&dev, assert.reply.large_blob_key, LARGEBLOB_KEY_SIZE, &blob) != FIDO_OK) {
        return 5;
    }

    // blob = credential_public_key (32) | signature(credential_public_key) (64)
    uint8_t *credential_public_key = blob.buffer;
    uint8_t *credential_public_key_signature = blob.buffer + 32;
    uint8_t updater_public_key[] = {0xA8, 0xEE, 0x4D, 0x2B, 0xD5, 0xAE, 0x09, 0x0A, 0xBC, 0xA9, 0x8A, 0x06, 0x6C, 0xA5, 0xB3, 0xA6, 0x22, 0x84, 0x89, 0xF5, 0x9E, 0x30, 0x90, 0x87, 0x65, 0x62, 0xB9, 0x79, 0x8A, 0xE7, 0x05, 0x15};

    // Verify the signature of the credential public key stored in the large blob.
    if(fido_ed25519_verify(credential_public_key_signature, updater_public_key, credential_public_key, 32) != 0) {
        return 6;
    }

    // Now, verify the assertion with the public key from the large blob.
    if (fido_assert_verify(&assert, COSE_ALGORITHM_EdDSA, credential_public_key) != FIDO_OK) {
        return 7;
    }

    if (fido_dev_close(&dev) != FIDO_OK) {
        return 8;
    }

    return 0;
}
