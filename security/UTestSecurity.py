#!/usr/bin/python3

import unittest
import base64
import binascii
from security import DHKeyExchange

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

        # print("+ server", base64.b64encode(server_derived_key))
        # print("+ server", server_derived_key.decode('hex'))
        print("+ server", binascii.hexlify(server_derived_key))
        # print("+ peer", peer_derived_key)

        self.assertEqual(server_derived_key, peer_derived_key)


if __name__ == "__main__":
    '''
    # For the next handshake we MUST generate another private key, but
    # we can reuse the parameters.
    '''
    unittest.main()
