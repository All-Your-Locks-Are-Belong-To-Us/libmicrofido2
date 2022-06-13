#pragma once

typedef struct fido_str_array {
    char **ptr;
    size_t len;
} fido_str_array_t;

typedef struct fido_opt_array {
    char **name;
    bool *value;
    size_t len;
} fido_opt_array_t;

typedef struct fido_byte_array {
    uint8_t *ptr;
    size_t len;
} fido_byte_array_t;

typedef struct fido_algo {
    char *type;
    int cose;
} fido_algo_t;

typedef struct fido_algo_array {
    fido_algo_t *ptr;
    size_t len;
} fido_algo_array_t;

typedef struct fido_cbor_info {
    fido_str_array_t  versions;       /* supported versions: fido2|u2f */
    fido_str_array_t  extensions;     /* list of supported extensions */
    fido_str_array_t  transports;     /* list of supported transports */
    unsigned char     aaguid[16];     /* aaguid */
    fido_opt_array_t  options;        /* list of supported options */
    uint64_t          maxmsgsize;     /* maximum message size */
    fido_byte_array_t protocols;      /* supported pin protocols */
    fido_algo_array_t algorithms;     /* list of supported algorithms */
    uint64_t          maxcredcntlst;  /* max credentials in list */
    uint64_t          maxcredidlen;   /* max credential ID length */
    uint64_t          fwversion;      /* firmware version */
    uint64_t          maxcredbloblen; /* max credBlob length */
    uint64_t          maxlargeblob;   /* max largeBlob array length */
} fido_cbor_info_t;
