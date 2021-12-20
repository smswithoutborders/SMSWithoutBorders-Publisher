#!/usr/bin/python3

'''
- https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dh/
'''

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64
import unittest

class DHKeyExchange:
    def __init__(self, parameters=None):
        # Generate some parameters. These can be reused.
        if parameters is None:
            print("* Generating parameters...")
            self.parameters = dh.generate_parameters(generator=2, key_size=2048)
        else:
            self.parameters = parameters

        # In a real handshake the peer is a remote client. For this
        # example we'll generate another local private key though. Note that in
        # a DH handshake both peers must agree on a common set of parameters.
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

    def get_keypairs(self):
        print("* Acquiring keypair values...")
        return self.private_key, self.public_key, self.parameters

    def generate_shared_key(self, public_key):
        print("* Generating shared key...")
        shared_key = self.private_key.exchange(public_key)
        # Perform key derivation.
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        print("* Derived key!")

        return derived_key

class TestDHKeyExchange(unittest.TestCase):
    def test_shared_keys(self):
        serverEnc = DHKeyExchange()
        server_private_key, server_public_key, server_parameters = \
                serverEnc.get_keypairs()

        peerEnc = DHKeyExchange(server_parameters)
        peer_private_key, peer_public_key, peer_parameters = \
                peerEnc.get_keypairs()

        server_derived_key = serverEnc.generate_shared_key(peer_public_key)
        peer_derived_key = peerEnc.generate_shared_key(server_public_key)

        # print("+ server", server_derived_key)
        # print("+ peer", peer_derived_key)

        self.assertEqual(server_derived_key, peer_derived_key)


if __name__ == "__main__":
    '''
    # For the next handshake we MUST generate another private key, but
    # we can reuse the parameters.
    '''
    unittest.main()
