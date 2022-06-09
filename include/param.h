#pragma once

#define CTAP_INIT_HEADER_LEN        7
#define CTAP_CONT_HEADER_LEN        5

/* Minimum length of a CTAP HID report in bytes. */
#define CTAP_MIN_REPORT_LEN         (CTAP_INIT_HEADER_LEN + 1)


/* Maximum message size in bytes. */
#ifndef FIDO_MAXMSG
#define FIDO_MAXMSG                 2048
#endif

/* CTAPHID command opcodes. */
#define CTAP_CMD_PING               0x01
#define CTAP_CMD_MSG                0x03
#define CTAP_CMD_LOCK               0x04
#define CTAP_CMD_INIT               0x06
#define CTAP_CMD_WINK               0x08
#define CTAP_CMD_CBOR               0x10
#define CTAP_CMD_CANCEL             0x11
#define CTAP_KEEPALIVE              0x3b
#define CTAP_FRAME_INIT             0x80

/* CTAPHID CBOR command opcodes. */
#define CTAP_CBOR_MAKECRED          0x01
#define CTAP_CBOR_ASSERT            0x02
#define CTAP_CBOR_GETINFO           0x04
#define CTAP_CBOR_CLIENT_PIN        0x06
#define CTAP_CBOR_RESET             0x07
#define CTAP_CBOR_NEXT_ASSERT       0x08
#define CTAP_CBOR_LARGEBLOB         0x0c
#define CTAP_CBOR_CONFIG            0x0d
#define CTAP_CBOR_BIO_ENROLL_PRE    0x40
#define CTAP_CBOR_CRED_MGMT_PRE     0x41
