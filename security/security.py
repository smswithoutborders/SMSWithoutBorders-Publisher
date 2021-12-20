#!/usr/bin/python3

'''
- https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dh/
'''

from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.asymmetric import dh 
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64
import binascii
import traceback

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
        print("* public key: ", self.public_key)
        print("++ public key", dir(self.public_key))
        print("++ private key", dir(self.private_key))

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



if __name__ == "__main__":

    import sys
    # public_key = base64.b64decode(sys.argv[1])
    public_key = sys.argv[1]
    print("+ public key", public_key)
    
    alice = DHKeyExchange()
    alice_private_key, alice_public_key, alice_parameters = \
            alice.get_keypairs()
    derived_key = alice.generate_shared_key(public_key)
    # print("+ server", base64.b64encode(derived_key))
    print("+ server", binascii.hexlify(derived_key))
