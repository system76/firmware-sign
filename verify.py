#!/usr/bin/env python3

import argparse
import nacl.encoding
import nacl.signing
import os
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--key', help='location of verifying key file, default ./keys/verify')
parser.add_argument('file', nargs='+', help='files to verify')
args = parser.parse_args()

if args.key == None:
    args.key = os.path.dirname(os.path.realpath(__file__)) + "/keys/verify"

verify_key_f = os.open(args.key, os.O_RDONLY)
verify_key_hex = os.read(verify_key_f, 64)
os.close(verify_key_f)

verify_key = nacl.signing.VerifyKey(verify_key_hex, encoder=nacl.encoding.HexEncoder)

for arg in args.file:
    f = open(arg, "rb")
    verified = verify_key.verify(f.read())
    f.close()

    f = open(arg + ".verified", "wb")
    f.write(verified)
    f.close()
