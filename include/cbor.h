#pragma once

// TODO: cbor_item_t is external
int cbor_parse_reply(const unsigned char *, size_t, void *,
                     int(*)(const cbor_item_t *, const cbor_item_t *, void *));

uint64_t fido_cbor_info_maxmsgsize(const fido_cbor_info_t *);
