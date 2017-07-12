# Firmware signing/verifying scripts

These scripts are used, along with a secret signing key, to sign and verify our firmware

- gen.py will create keys in the `keys` directory, with mode 0400
- sign.py will sign files, producing a signed binary with `keys/sign`
- verify.py will verify files, producing the original file if the signature matches with `keys/verify`

You may distribute the `keys/verify` file to others. Keep `keys/sign` secret!
