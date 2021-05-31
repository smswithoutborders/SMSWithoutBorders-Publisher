#!/bin/python
import secrets
from Cryptodome.Hash import SHA256, SHA1
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
        cipher = AES.new(bytes(key, 'utf-8'), AES.MODE_CBC, bytes(iv, 'utf-8'))
        b64data = b64decode(data)
        decryptedData = cipher.decrypt(b64data)
        decryptedData = unpad(decryptedData, AES.block_size)
        print(decryptedData)
        decryptedData = str(decryptedData, 'utf-8')
        decryptedData = decryptedData.replace('\n', '')
        # print(decryptedData)
        return decryptedData

    def __read_publickey(self):
        return "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDJKfzNwH+Kdd+d1q8m8FFr5EX+gaAUAumDf+b9zjMDaHEWUqXnrCcLVy2FTkjcCOylkX+xmrlOhpYdwjrMrZ+PIfi+ok+FjrRIj1KfjAzJZd77+spS7oxcyWhw1wBhutGyOs2x4YWDnRjvhVhvuT+/aVdQjQroAhz7g1ShjeTuVeTc01K9HddiEixihF5lelLde8+AHa9V/ov6prtWD7momg0bF1J9FMp8zDKDnHPR6ptND/QhbhsMof+vAh/5x4vRcbFjRNxOqvGQxyqyzl2VxdxXBhJJ2UiumvcnY9XN3g30pvMff2zO7WpmM4wLOoRo0nijTTAerpiSlUz7jZZ2xhIc5YwTG1iSYj2GEWtN+fISfEoaurezPvigLiVuyolksVX4nMvBcSoHe4fb8sqchFAJuTT/6ko1NsXnrNGs4wKXA3JQ+riYPgxWrh/quTgwMvyErmuGoCPcm/XvkDy3GEHY3z+DXPQZgSYFERE/RZz2O+CpTnb7bBd8n6TElfM= sherlock@manjaro"


if __name__ == "__main__":
    securityLayer = SecurityLayer()
    '''
    data='8gjJxfN1dVknIqYiarspwZoWwyBwojecA5+ohHPgaNI='
    key='7e8555fe4d80865f6a98c21521f2db53'
    iv='1f52ed515871c913'

    iv = securityLayer.aes_decrypt(data, key, iv)
    print("decrypted IV:", iv)

    data='eG91S0NDbURnQWtlVk9IakJtL3ljQT09Cg=='
    decryptedData = securityLayer.aes_decrypt(data, key, iv, True)
    print(decryptedData)
    '''

    def_key='d5f0620aa458f99be129729340d146c1'
    def_iv='D135AC9F95F208D0BD7184DF5CA99CAD35BDEB7D85364F524110BC29F23633A0822AAC2F0288DB2BE0BED4F9EC42B0220DB21E03801F217D029DF4B729535697'[:16]
    # print("[+] def_iv:", def_iv)
    data='o1tqLSITdjsXlCjYYZGKjEVDiVELvvdrYlzxoHe6kGk=_piKULBawhwh+Fu7GhsvQJtAe48jAps0l6StWKXqxxOs='
    split_data=data.split('_')

    encrypted_iv=split_data[0]
    encrypted_data=split_data[1]
    print("[+] Encrypted IV:", encrypted_iv)
    print("[+] Encrypted Data:", encrypted_data)

    decrypted_iv=securityLayer.aes_decrypt(encrypted_iv, def_key, def_iv)
    print("\n[+] Decrypted IV:", decrypted_iv)
    # decrypted_iv=str(b64decode(decrypted_iv), 'utf-8')
    decrypted_data=securityLayer.aes_decrypt(encrypted_data, def_key, decrypted_iv)
    print("[+] Decrypted Data:", decrypted_data)
