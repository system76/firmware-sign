#!/usr/bin/env python3

import nacl.encoding
import nacl.signing
import os

keys = os.path.dirname(os.path.realpath(__file__)) + "/keys"

if os.path.isdir(keys):
    print("keys directory already exits")
else:
    os.mkdir(keys, 0o700)

if os.path.isfile(keys + "/sign"):
    print("keys/sign already exists")

    sign_key_f = os.open(keys + "/sign", os.O_RDONLY)
    sign_key_hex = os.read(sign_key_f, 64)
    os.close(sign_key_f)

    sign_key = nacl.signing.SigningKey(sign_key_hex, encoder=nacl.encoding.HexEncoder)
else:
    sign_key = nacl.signing.SigningKey.generate()
    sign_key_hex = sign_key.encode(encoder=nacl.encoding.HexEncoder)

    sign_key_f = os.open(keys + "/sign", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    os.write(sign_key_f, sign_key_hex)
    os.close(sign_key_f)

if os.path.isfile(keys + "/verify"):
    print("keys/verify already exists")
else:

    verify_key = sign_key.verify_key
    verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)

    verify_key_f = os.open(keys + "/verify", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    os.write(verify_key_f, verify_key_hex)
    os.close(verify_key_f)

os.chmod(keys, 0o500)
