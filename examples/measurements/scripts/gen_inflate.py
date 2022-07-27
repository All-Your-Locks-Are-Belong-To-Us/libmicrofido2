#!/bin/env python

import zlib
import os

hex_arrayify = lambda x: '{ ' + ', '.join([f'0x{i:02x}' for i in x]) + ' }'

uncompressed = os.urandom(576)
print(f'const uint8_t uncompressed[] = {hex_arrayify(uncompressed)};')

c = zlib.compressobj(wbits=-15)
c.compress(uncompressed)
compressed = c.flush()
print(f'const uint8_t source[] = {hex_arrayify(compressed)};')
