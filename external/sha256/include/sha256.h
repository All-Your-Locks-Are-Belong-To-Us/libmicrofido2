/*********************************************************************
* Filename:   sha256.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.
**********************************************************************
* Source: https://github.com/B-Con/crypto-algorithms
* Modified by:
    Felix Gohla, Konrad Hanff, Tobias Kantusch, Quentin Kuth, Felix Roth
*********************************************************************/

#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>
#include <stdint.h>

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE (32)                  // SHA256 outputs a 32 byte digest
#define SHA256_DIGEST_SIZE SHA256_BLOCK_SIZE    // SHA256 outputs a 32 byte digest

/**************************** DATA TYPES ****************************/
typedef uint8_t BYTE;  // 8-bit byte
typedef uint32_t WORD; // 32-bit word, change to "long" for 16-bit machines

typedef struct {
    BYTE data[64];
    WORD datalen;
    uint64_t bitlen;
    WORD state[8];
} SHA256_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len);
void sha256_final(SHA256_CTX *ctx, BYTE hash[]);

void sha256(const BYTE data[], size_t len, BYTE hash[]);

#endif   // SHA256_H
