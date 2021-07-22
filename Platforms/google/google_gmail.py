import os.path
import base64
import json

from email.mime.text import MIMEText as MIMEText
from googleapiclient.discovery import build

from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request 
from google.oauth2.credentials import Credentials 

from . import quickstart as googleAuths
# print("GMAIL")

def create_message(sender, to, subject, message_text, sender_name=None):
    message = MIMEText(message_text)
    message['to'] = to

    if sender_name is None:
        message['from'] = sender
    else:
        message['from'] = f"{sender_name} <{sender}>"

    message['subject'] = subject
    print(message)
    return {'raw' : base64.urlsafe_b64encode(message.as_string().encode('utf-8'))}

def send(sender, to, subject, message_text, sender_name, userDetails):
    print(">> sending email....")
    try:
        if userDetails is not None:
            service = googleAuths.main(userDetails)
        else:
            # service = googleAuths.main()
            print("[-] No user credentials for gmail available")
            raise Exception("Missing user credentials to send...")
    except Exception as error:
        raise Exception(error)
    else:
        message = create_message(sender, to, subject, message_text, sender_name)
        message['raw'] = message['raw'].decode('utf-8')

        print(">> Gmail Send Service...")
        print(message)
        print(service)

        try:
            user_id = "me"
            message = (service.users().messages().send(userId=user_id, body=message).execute())
            print(message)

        except Exception as error:
            print(f">> An error occured: {error}")
            raise Exception(error)

def execute(protocol, body, userDetails):
    sender=userDetails["profile"]["data"]["email"]
    name=userDetails["profile"]["data"]["name"]
    split_body = body.split(':')
    to=split_body[0]
    subject=split_body[1]
    message_text = ":".join(split_body[2:])

    # TODO: Using this as a todo, but should change the contents to be more dynamic
    # userDetails["token_path"] = "Platforms/google/token.json"
    # userDetails["credentials_path"] = "Platforms/google/credentials.json"

    print(f"\n\tsender: {sender}\n\tsubject: {subject}\n\tto: {to}\n\tmessage_text: {message_text}\n\tname: {name}")

    client_id=None
    client_secret=None

    # TODO: Replace to read credentials from current dir
    creds_path = os.path.join(os.path.dirname(__file__), '', 'credentials.json')
    with open(creds_path) as creds:
        creds = json.load( creds )
        for key in creds.keys():
            if "client_id" in creds[key] and "client_secret" in creds[key]:
                client_id = creds[key]["client_id"]
                client_secret = creds[key]["client_secret"]
                break
    userDetails["token"]["client_id"] = client_id
    userDetails["token"]["client_secret"] = client_secret

    userDetails["token"]["scope"] = userDetails["token"]["scope"].replace("openid ", '');
    userDetails["token"]["scope"] = userDetails["token"]["scope"].split(' ')

    try:
        send(sender=sender, to=to, subject=subject, message_text=message_text, sender_name=name, userDetails=userDetails)
    except Exception as error:
        raise Exception(error)
    else:
        return True

if __name__ == '__main__':
    sender_name = input(">> Your name:")
    sender = input(">> Sender email address:")
    to = input(">> Receipient email address:")
    subject = input(">> Email subject:")
    message_text=input("[+] Message:")

    send(sender, to, subject, message_text, sender_name)
