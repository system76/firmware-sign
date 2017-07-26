"""
Unit tests for the `pihsm.verify` module.
"""


from unittest import TestCase
import os
import time

from nacl.signing import SigningKey, VerifyKey
import nacl.exceptions

from ..sign import Signer
from .. import verify


class TestFunctions(TestCase):
    def test_verify_signature(self):
        private = os.urandom(32)
        sk = SigningKey(private)
        previous = os.urandom(64)
        counter = os.urandom(16)
        timestamp = os.urandom(16)
        public = bytes(sk.verify_key)
        msg = os.urandom(64)

        # Valid sig, correct pub key in signing header:
        signing_form = b''.join([
            previous,
            counter,
            timestamp,
            public,
            msg
        ])
        sm = sk.sign(signing_form)
        c = verify.verify_signature(bytes(sm), public)
        self.assertEqual(type(c), verify.Child)
        self.assertEqual(c.signature, sm.signature)
        self.assertEqual(c.previous, previous)
        self.assertEqual(c.counter.to_bytes(16, 'little'), counter)
        self.assertEqual(c.timestamp.to_bytes(16, 'little'), timestamp)
        self.assertEqual(c.public, public)
        self.assertEqual(c.message, msg)

        # Signed message has been modified with different public key:
        bad_public = os.urandom(32)
        signed = b''.join([
            sm.signature,
            previous,
            counter,
            timestamp,
            bad_public,
            msg
        ])
        with self.assertRaises(nacl.exceptions.BadSignatureError):
            verify.verify_signature(signed, public)

        # Signature is valid, but wrong public key was used in signing header:
        signing_form = b''.join([
            previous,
            counter,
            timestamp,
            bad_public,
            msg
        ])
        signed = bytes(sk.sign(signing_form))
        with self.assertRaises(ValueError) as cm:
            verify.verify_signature(signed, public)
        self.assertEqual(str(cm.exception),
            'embebbed pubkey mismatch: {!r} != {!r}'.format(bad_public, public)
        )

    def test_verify_parent(self):
        private = os.urandom(32)
        s = Signer(private)
        public = s.public

        ts1 = int(time.time())
        ts0 = ts1 - 1776
        msg0 = os.urandom(31)
        msg1 = os.urandom(33)
        sig0 = s.sign(ts0, msg0)
        sig1 = s.sign(ts1, msg1)

