"""

FIXME: Originating node should have a counter of zero, but use a random nonce
for the previous node.  There's no reason for the original node to be
deterministic.


| Signature  | Previous Sig. | Counter    | Timestamp  | Public Key | Message    |
| (64 bytes) | (64 bytes)    | (16 bytes) | (16 bytes) | (32 bytes) | (1+ bytes) |
"""

from hashlib import sha384

from nacl.signing import SigningKey





def hash_manifest(data):
    return sha384(data).hexdigest()
    



class Signer:
    def __init__(self, private, previous=(b'\x00' * 64), counter=0):
        assert type(private) is bytes and len(private) == 32
        assert type(previous) is bytes and len(previous) == 64
        assert type(counter) is int and 0 <= counter < 2**64
        self.key = SigningKey(private)
        self.previous = (b'\x00' * 64 if previous is None else previous)
        self.counter = counter
        self.public = bytes(self.key.verify_key)

    def build_signing_form(self, timestamp, message):
        return b''.join([
            self.previous,
            self.counter.to_bytes(16, 'little'),
            int(timestamp).to_bytes(16, 'little'),
            self.public,
            message
        ])

    def sign(self, timestamp, message):
        rsp = bytes(self.key.sign(self.build_signing_form(timestamp, message)))
        self.previous = rsp[:64]
        self.counter += 1
        return rsp

