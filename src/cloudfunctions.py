#!/bin/python


import configparser
import requests
import os

CONFIGS = configparser.ConfigParser(interpolation=None)

CONFIGS.read("config.router.ini")
CLOUD_URL = CONFIGS["CLOUD_API"]["url"]
# from ldatastore import Datastore


def check_ssl():
    print( "[+]:", CONFIGS["SSL"]["PEM"] )
    return os.path.isfile( CONFIGS["SSL"]["KEY"] ) and os.path.isfile(CONFIGS["SSL"]["CRT"])

def cloudAcquireGrantLevelHashes(sessionId):
    datastore = Datastore()
    userId = datastore.findUserBySessionId(sessionId)
    try:
        cloud_url_acquire_platforms = f"{CLOUD_URL}/users/grant-level/hashvalue"
        print(">> CLOUD_URL: ", cloud_url_auth_users)
        request=None

        if check_ssl():
            print("[+] going ssl...")
            request = requests.post(cloud_url_auth_users, json={"user_id":userId}, cert=(CONFIGS["SSL"]["CRT"], CONFIGS["SSL"]["KEY"]))

        else:
            request = requests.post(cloud_url_auth_users, json={"user_id":userId}))
        print(request.text)
    except Exception as error:
        raise Exception(error)


def cloudAcquireUserPlatforms(sessionId):
    datastore = Datastore()
    userId = datastore.findUserBySessionId(sessionId)
    try:
        cloud_url_acquire_platforms = f"{CLOUD_URL}/users/platforms"
        print(">> CLOUD_URL: ", cloud_url_auth_users)
        request=None

        if check_ssl():
            print("[+] going ssl...")
            request = requests.post(cloud_url_auth_users, json={"user_id":userId}, cert=(CONFIGS["SSL"]["CRT"], CONFIGS["SSL"]["KEY"]))

        else:
            request = requests.post(cloud_url_auth_users, json={"user_id":userId}))
        print(request.text)
    except Exception as error:
        raise Exception(error)

def cloudAuthUser(platform, protocol, phonenumber):
    try:
        cloud_url_auth_users = f"{CLOUD_URL}/users/profiles"
        print(">> CLOUD_URL: ", cloud_url_auth_users)
        request=None

        if check_ssl():
            print("[+] going ssl...")
            request = requests.post(cloud_url_auth_users, json={"platform":platform, "protocol":protocol, "phone_number":phonenumber}, cert=(CONFIGS["SSL"]["CRT"], CONFIGS["SSL"]["KEY"]))
            # request = requests.post(cloud_url_auth_users, json={"platform":platform, "protocol":protocol, "phone_number":phonenumber}, verify='/var/www/ssl/server.key')

        else:
            request = requests.post(cloud_url_auth_users, json={"platform":platform, "protocol":protocol, "phone_number":phonenumber})
        # request = requests.post(cloud_url_auth_users, json={"platform":platform, "protocol":protocol, "phone_number":phonenumber}, verify=False)
        print(request.text)
    except Exception as error:
        raise Exception(error)
    else:
        if not "status_code" in request and request.status_code is not 200:
            return None
        if not "auth_key" in request.json():
            return None
        else:
            request = request.json()
            
            print("[+] User authenticated... Fetching tokens:", platform)
            # with everything authenticated, let's get the tokens

            cloud_url_auth_users = CLOUD_URL + "/users/stored_tokens"
            print(">> CLOUD_URL: ", cloud_url_auth_users)
            # request = requests.post(cloud_url_auth_users, json={"auth_key":request["auth_key"]})
            if check_ssl():
                request = requests.post(cloud_url_auth_users, json={"auth_key":request["auth_key"], "platform":platform}, cert=(CONFIGS["SSL"]["CRT"], CONFIGS["SSL"]["KEY"]))
            else:
                request = requests.post(cloud_url_auth_users, json={"auth_key":request["auth_key"], "platform":platform})

            if not "status_code" in request and request.status_code is not 200:
                return None
            
            req_json = request.json()
            print("text:", req_json)

            if len(req_json) > 0:
                return req_json

            return None
