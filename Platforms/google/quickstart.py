from __future__ import print_function
import os.path
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.readonly']

def main( userDetails ):
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    # token_path = 'token.json'
    credentials_path = 'Platforms/google/credentials.json'

    '''
    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)
    '''
    # creds = Credentials.from_authorized_user_info(userDetails, SCOPES)
    if "token" in userDetails:
        print(userDetails["token"]["scope"])
        print(userDetails["token"])
        creds = Credentials.from_authorized_user_info(userDetails["token"], userDetails["token"]["scope"])
        print(creds)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        '''
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                credentials_path, SCOPES)
            # creds = flow.run_local_server(port=0)
            creds = flow.run_local_server()
        # Save the credentials for the next run
        with open(token_path, 'w') as token:
            token.write(creds.to_json())
        '''
        print(f"\t\t[+] New creds from refresh: {creds.to_json()}")

    service = build('gmail', 'v1', credentials=creds)
    # gmail.send( service )
    return service

    # Call the Gmail API
    '''
    results = service.users().labels().list(userId='me').execute()
    labels = results.get('labels', [])

    if not labels:
        print('No labels found.')
    else:
        print('Labels:')
        for label in labels:
            print(label['name'])
    '''

if __name__ == '__main__':
    print(main())
