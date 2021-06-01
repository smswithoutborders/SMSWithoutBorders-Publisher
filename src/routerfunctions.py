#!/bin/python


# gmail = subject:to:message
# format = platform:protocol:body

# sms = platform:protocol:body{subject:to:message}
import traceback
from . datastore import Datastore
from . securitylayer import SecurityLayer

def decrypt_series(data, user_details):
    securityLayer = SecurityLayer()
    def_key = user_details['shared_key']
    def_iv = user_details['password_hash']

    iv=data[:16].replace('\n', '')
    data=data[16:].replace('\n', '')
    print(f"iv: {iv}\ndata:{data}")

    decrypted_data=securityLayer.aes_decrypt(data, def_key, iv)
    print(decrypted_data.decode("utf-8"))

    return decrypted_data.decode("utf-8")


def routerParseText(text, user_details):
    '''
    example:
        gmail:send:afkanerd@gmail.com:Hello world:This is a test message! Hello
    '''

    '''
    header=(platform:protocol)
    body
    '''
    try:
        text = decrypt_series(text, user_details)
        split_text = text.split(":")
        if len(split_text) > 2:
            provider=split_text[0]
            platform=split_text[1]
            protocol=split_text[2]
            body=":".join(split_text[3:])
            '''
            print(f"PLATFORM: {platform}")
            print(f"PROTOCOL: {protocol}")
            print(f"BODY: {body}")
            '''
            return {"provider":provider, "platform":platform, "protocol":protocol, "body":body}
        else:
            return None
    except Exception as error:
        print(traceback.format_exc())
