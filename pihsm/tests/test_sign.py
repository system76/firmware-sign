from unittest import TestCase
import os
import time

from nacl.signing import SigningKey, VerifyKey

from .. import sign


class TestFunctions(TestCase):
    def test_hash_manifest(self):
        self.assertEqual(sign.hash_manifest(b'hello, world'),
            '1fcdb6059ce05172a26bbe2a3ccc88ed5a8cd5fc53edfd9053304d429296a6da23b1cd9e5c9ed3bb34f00418a70cdb7e'
        )


class TestSigner(TestCase):
    def test_init(self):
        private = os.urandom(32)
        s = sign.Signer(private)
        self.assertEqual(s.previous, b'\x00' * 64)
        self.assertEqual(s.counter, 0)

    def test_build_signing_form(self):
        private = os.urandom(32)
        public = bytes(SigningKey(private).verify_key)
        previous = b'\x00' * 64
        cnt_b = (0).to_bytes(16, 'little')
        ts = int(time.time())
        ts_b = ts.to_bytes(16, 'little')
        msg = os.urandom(64)

        s = sign.Signer(private)
        self.assertEqual(
            s.build_signing_form(ts, msg),
            b''.join([
                previous,
                cnt_b,
                ts_b,
                public,
                msg
            ])
        )

    def test_sign(self):
        private = os.urandom(32)
        public = bytes(SigningKey(private).verify_key)
        previous = b'\x00' * 64
        cnt_b = (0).to_bytes(16, 'little')
        ts = int(time.time())
        ts_b = ts.to_bytes(16, 'little')
        msg = os.urandom(64)

        signing_form = b''.join([
            previous,
            cnt_b,
            ts_b,
            public,
            msg
        ])

        s = sign.Signer(private)
        rsp = s.sign(ts, msg)
        self.assertEqual(type(rsp), bytes)
        self.assertEqual(len(rsp), len(signing_form) + 64)
        self.assertEqual(rsp[64:], signing_form)

        v = VerifyKey(public)
        self.assertEqual(v.verify(rsp), signing_form)

        previous = s.previous
        self.assertEqual(previous, rsp[:64])
        self.assertEqual(s.counter, 1)
        cnt_b = (1).to_bytes(16, 'little')
        signing_form = b''.join([
            previous,
            cnt_b,
            ts_b,
            public,
            msg
        ])

        rsp = s.sign(ts, msg)
        self.assertEqual(type(rsp), bytes)
        self.assertEqual(len(rsp), len(signing_form) + 64)
        self.assertEqual(rsp[64:], signing_form)

        old = previous
        previous = s.previous
        self.assertNotEqual(previous, old)
        self.assertEqual(previous, rsp[:64])
        self.assertEqual(s.counter, 2)

