#!/usr/bin/env python3

import nacl.encoding
import nacl.signing
import os
import sys

if len(sys.argv) < 2:
    sys.stderr.write("verify.py [file] ...\n")
    exit(1)

verify_key_f = os.open("keys/verify", os.O_RDONLY)
verify_key_hex = os.read(verify_key_f, 64)
os.close(verify_key_f)

verify_key = nacl.signing.VerifyKey(verify_key_hex, encoder=nacl.encoding.HexEncoder)

for arg in sys.argv[1:]:
    f = open(arg, "rb")
    verified = verify_key.verify(f.read())
    f.close()

    f = open(arg + ".verified", "wb")
    f.write(verified)
    f.close()
