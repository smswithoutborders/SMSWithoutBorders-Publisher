#!/bin/python
import secrets
from Cryptodome.Hash import SHA512, SHA256, SHA1
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import PKCS1_OAEP, AES
from base64 import b64decode,b64encode
from Cryptodome.Signature import pss
from Cryptodome.Util.Padding import pad, unpad

class SecurityLayer():
    def __init__(self):
        self.publicKey = self.__read_publickey()

    def get_public_key(self):
        return self.publicKey

    def get_shared_key(self):
        # TODO: this is the idea
        # return encrypt(secrets.token_hex(32), publicKey)
        return secrets.token_hex(16)

    @staticmethod
    def sha512Hash(data):
        h = SHA512.new()
        h.update(bytes(data, 'utf-8'));
        return h.hexdigest()


    def rsa_encrypt(self, data, key):
        data = bytes(data, 'utf-8')
        key = b64decode(key)
        key = RSA.importKey(key)
        cipher_rsa = PKCS1_OAEP.new(key=key, hashAlgo=SHA256.new(), mgfunc=lambda x,y: pss.MGF1(x,y, SHA1))
        # cipher_rsa = PKCS1_v1_5.new(key=key)
        return cipher_rsa.encrypt(data)
        # return b64encode(cipher_rsa.encrypt(data))
        # return b64decode(cipher_rsa.encrypt(data)).decode('utf-8')

    def aes_decrypt(self, data, key, iv, decodeIV=False):
        if decodeIV:
            iv=str(b64decode(iv), 'utf-8')
        # cipher = AES.new(bytes(key, 'utf-8'), AES.MODE_CBC, bytes(iv, 'utf-8'))
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
        b64data = b64decode(data)
        decryptedData = cipher.decrypt(b64data)
        decryptedData = unpad(decryptedData, AES.block_size)
        # decryptedData = str(decryptedData, 'utf-8')
        # decryptedData = decryptedData.replace('\n', '')
        # print(decryptedData)
        return decryptedData

    #  TODO:
    def __read_publickey(self):
        return "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDJKfzNwH+Kdd+d1q8m8FFr5EX+gaAUAumDf+b9zjMDaHEWUqXnrCcLVy2FTkjcCOylkX+xmrlOhpYdwjrMrZ+PIfi+ok+FjrRIj1KfjAzJZd77+spS7oxcyWhw1wBhutGyOs2x4YWDnRjvhVhvuT+/aVdQjQroAhz7g1ShjeTuVeTc01K9HddiEixihF5lelLde8+AHa9V/ov6prtWD7momg0bF1J9FMp8zDKDnHPR6ptND/QhbhsMof+vAh/5x4vRcbFjRNxOqvGQxyqyzl2VxdxXBhJJ2UiumvcnY9XN3g30pvMff2zO7WpmM4wLOoRo0nijTTAerpiSlUz7jZZ2xhIc5YwTG1iSYj2GEWtN+fISfEoaurezPvigLiVuyolksVX4nMvBcSoHe4fb8sqchFAJuTT/6ko1NsXnrNGs4wKXA3JQ+riYPgxWrh/quTgwMvyErmuGoCPcm/XvkDy3GEHY3z+DXPQZgSYFERE/RZz2O+CpTnb7bBd8n6TElfM= sherlock@manjaro"


if __name__ == "__main__":
    securityLayer = SecurityLayer()

    def_key='26dce55aa7ce6238240986e422d16495'
    def_iv='D135AC9F95F208D0BD7184DF5CA99CAD35BDEB7D85364F524110BC29F23633A0822AAC2F0288DB2BE0BED4F9EC42B0220DB21E03801F217D029DF4B729535697'[:16]
    data='N588SMCM2QF83T34QAsHvQW1wVjROIPxYASZs57lF14pIP+BxGevhGOx7YP9Ih0K3psX2ownAvzkcqbUK1+OkaBdhZ2QWAl5B+rxRw=='

    iv=data[:16]
    data=data[16:]
    print(f"iv: {iv}\ndata:{data}")

    decrypted_data=securityLayer.aes_decrypt(data, def_key, iv)
    print(decrypted_data.decode("utf-8"))
