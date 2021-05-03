#!/bin/python
import secrets
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from base64 import b64decode,b64encode


class SecurityLayer():
    def __init__(self):
        self.publicKey = self.__read_publickey()

    def get_public_key(self):
        return self.publicKey

    def get_shared_key(self):
        # TODO: this is the idea
        # return encrypt(secrets.token_hex(32), publicKey)
        return secrets.token_hex(32)

    def rsa_encrypt(self, data, key):
        data = bytes(data, 'utf-8')
        key = b64decode(key)
        key = RSA.importKey(key)
        cipher_rsa = PKCS1_OAEP.new(key)
        return b64encode(cipher_rsa.encrypt(data))

    def __read_publickey(self):
        return "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDJKfzNwH+Kdd+d1q8m8FFr5EX+gaAUAumDf+b9zjMDaHEWUqXnrCcLVy2FTkjcCOylkX+xmrlOhpYdwjrMrZ+PIfi+ok+FjrRIj1KfjAzJZd77+spS7oxcyWhw1wBhutGyOs2x4YWDnRjvhVhvuT+/aVdQjQroAhz7g1ShjeTuVeTc01K9HddiEixihF5lelLde8+AHa9V/ov6prtWD7momg0bF1J9FMp8zDKDnHPR6ptND/QhbhsMof+vAh/5x4vRcbFjRNxOqvGQxyqyzl2VxdxXBhJJ2UiumvcnY9XN3g30pvMff2zO7WpmM4wLOoRo0nijTTAerpiSlUz7jZZ2xhIc5YwTG1iSYj2GEWtN+fISfEoaurezPvigLiVuyolksVX4nMvBcSoHe4fb8sqchFAJuTT/6ko1NsXnrNGs4wKXA3JQ+riYPgxWrh/quTgwMvyErmuGoCPcm/XvkDy3GEHY3z+DXPQZgSYFERE/RZz2O+CpTnb7bBd8n6TElfM= sherlock@manjaro"



if __name__ == "__main__":
    securityLayer = SecurityLayer()
    
    key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwo7R0xMsbmt88EMe9i5hRSC4pgOfcUsKO0b4R/X5TdTVqeuyoy2lyip1PYagcBajpC6oYjKgj2oRp3hRaYk1h0QyNw50l9fJGR7fAILN3CmUvLKOEtcHE8phvDeY4aOP8ivaVuj+imWk4MzLDisfVS7ybJXlmA/NWVoVuTyWKCTRyxXwk3NayTKOlytvXmjjWoknccCTlMwY1ILD6S3wt/qaDVQ3dm8Yf2gZhK/pLuIgOaer0dEaOK+wJYDbtg4FPlH9TXp2d9g7CfsssFnNLu3mZkisiVchDK8Kcu9ejY5yIaf8jlFrwVpKFfQLB4AO/cwdG+owVEPn0dkvLxp7eQIDAQAB"
    en_msg=securityLayer.rsa_encrypt("Hello world", key)
    print(type(en_msg))
    print(type(str(en_msg)))
