#!/usr/bin/env python3

import nacl.encoding
import nacl.signing
import os
import sys

if len(sys.argv) < 2:
    sys.stderr.write("sign.py [file] ...\n")
    exit(1)

sign_key_f = os.open("keys/sign", os.O_RDONLY)
sign_key_hex = os.read(sign_key_f, 64)
os.close(sign_key_f)

sign_key = nacl.signing.SigningKey(sign_key_hex, encoder=nacl.encoding.HexEncoder)

for arg in sys.argv[1:]:
    f = open(arg, "rb")
    signed = sign_key.sign(f.read())
    f.close()

    f = open(arg + ".signed", "wb")
    f.write(signed)
    f.close()
