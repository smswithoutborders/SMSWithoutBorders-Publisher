#!/bin/python


# gmail = subject:to:message
# format = platform:protocol:body

# sms = platform:protocol:body{subject:to:message}
from . datastore import Datastore

def decrypt_series(data, user_details):
    # def_key='d5f0620aa458f99be129729340d146c1'
    def_key = user_details['shared_key']
    # def_iv='D135AC9F95F208D0BD7184DF5CA99CAD35BDEB7D85364F524110BC29F23633A0822AAC2F0288DB2BE0BED4F9EC42B0220DB21E03801F217D029DF4B729535697'[:16]
    def_iv = user_details['password_hash']

    # print("[+] def_iv:", def_iv)
    # data='wIHcLqi7BRgLYuBQL+sI8Ij/bT2Xpq5iJ0DTX4VHE1c=_mX2JQLKTQ3vtZ2+FSOwHlwm1JdfwH0URP6t2HjiawoI='
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


def routerParseText(text, user_details):
    '''
    example:
        gmail:send:afkanerd@gmail.com:Hello world:This is a test message! Hello
    '''

    '''
    header=(platform:protocol)
    body
    '''
    text = decrypt_series(text, user_details)
    split_text = text.split(":")
    if len(split_text) > 2:
        platform=split_text[0]
        protocol=split_text[1]
        body=":".join(split_text[2:])
        '''
        print(f"PLATFORM: {platform}")
        print(f"PROTOCOL: {protocol}")
        print(f"BODY: {body}")
        '''
        return {"platform":platform, "protocol":protocol, "body":body}
    else:
        return None
