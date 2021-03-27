#!/bin/python


# gmail = subject:to:message
# format = platform:protocol:body

# sms = platform:protocol:body{subject:to:message}
'''
example:
    gmail:send:Hello world:afkanerd@gmail.com:This is a test message! Hello
'''

def routerParseText(text):
    '''
    header=(platform:protocol)
    body
    '''
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
