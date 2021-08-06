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

if __name__ == "__main__":
    ''' broken test - please do not use, write a functional test by importing the lib '''
    securityLayer = SecurityLayer()

    def_key=''
    def_iv=''[:16]
    data=''

    iv=data[:16]
    data=data[16:]
    print(f"iv: {iv}\ndata:{data}")

    decrypted_data=securityLayer.aes_decrypt(data, def_key, iv)
    print(decrypted_data.decode("utf-8"))
