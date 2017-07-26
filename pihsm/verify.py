"""

"""

from collections import namedtuple

from nacl.signing import VerifyKey



Child = namedtuple('Child', 'signature previous counter timestamp public message')


def verify_signature(signed, public):
    vk = VerifyKey(public)
    vk.verify(signed)
    child = Child(
        signed[0:64],
        signed[64:128],
        int.from_bytes(signed[128:144], 'little'),
        int.from_bytes(signed[144:160], 'little'),
        signed[160:192],
        signed[192:],
    )
    if child.public != public:
        raise ValueError(
            'embebbed pubkey mismatch: {!r} != {!r}'.format(child.public, public)
        )
    return child


def verify_parent(signed, child):
    parent = verify_signature(signed, child.public)
    return parent



