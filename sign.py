#!/usr/bin/env python3

import argparse
import nacl.encoding
import nacl.signing
import os
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--key', help='location of signing key file, default ./keys/sign')
parser.add_argument('file', nargs='+', help='files to sign')
args = parser.parse_args()

if args.key == None:
    args.key = os.path.dirname(os.path.realpath(__file__)) + "/keys/sign"

sign_key_f = os.open(args.key, os.O_RDONLY)
sign_key_hex = os.read(sign_key_f, 64)
os.close(sign_key_f)

sign_key = nacl.signing.SigningKey(sign_key_hex, encoder=nacl.encoding.HexEncoder)

for arg in args.file:
    f = open(arg, "rb")
    signed = sign_key.sign(f.read())
    f.close()

    f = open(arg + ".signed", "wb")
    f.write(signed)
    f.close()
