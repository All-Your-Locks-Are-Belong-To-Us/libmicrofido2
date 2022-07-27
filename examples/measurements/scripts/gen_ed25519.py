#!/bin/env python

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

hex_arrayify = lambda x: '{ ' + ', '.join([f'0x{i:02x}' for i in x]) + ' }'

key = ed25519.Ed25519PrivateKey.generate()
key_bytes = key.private_bytes(encoding=serialization.Encoding.Raw,format=serialization.PrivateFormat.Raw,encryption_algorithm=serialization.NoEncryption())
print(f'const uint8_t private_key[] = {hex_arrayify(key_bytes)};')

pub_bytes = key.public_key().public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)
print(f'const uint8_t public_key[] = {hex_arrayify(pub_bytes)};')

message = 576 * b'f'
print(f'const uint8_t message[] = {hex_arrayify(message)};')

signature = key.sign(message)
print(f'const uint8_t signature[] = {hex_arrayify(signature)};')
