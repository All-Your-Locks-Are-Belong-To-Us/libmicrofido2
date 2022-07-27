#!/bin/env python

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

hex_arrayify = lambda x: '{ ' + ', '.join([f'0x{i:02x}' for i in x]) + ' }'

key = AESGCM.generate_key(bit_length=256)
print(f'const uint8_t key[] = {hex_arrayify(key)};')

aad = b'fidoonmicros'
print(f'const uint8_t associated_data[] = "{aad.decode()}";')

nonce = os.urandom(12)
print(f'const uint8_t nonce[] = {hex_arrayify(nonce)};')

data = 576 * b'f'

aesgcm = AESGCM(key)
encrypted = aesgcm.encrypt(nonce, data, aad)
ct = encrypted[:-16]
tag = encrypted[-16:]
print(f'const uint8_t ciphertext[] = {hex_arrayify(ct)};')
print(f'const uint8_t tag[] = {hex_arrayify(tag)};')
