#!/bin/env python

import hashlib

hex_arrayify = lambda x: '{ ' + ', '.join([f'0x{i:02x}' for i in x]) + ' }'

data = 576 * b'f'
print(f'const uint8_t data[] = {hex_arrayify(data)};')

hash = hashlib.sha256(data).digest()
print(f'const uint8_t hash[] = {hex_arrayify(hash)};')
