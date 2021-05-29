#!/bin/python


import configparser
import requests
import os
from . datastore import Datastore

CONFIGS = configparser.ConfigParser(interpolation=None)

PATH_CONFIG_FILE = os.path.join(os.path.dirname(__file__), '../configs', 'config.router.ini')
CONFIGS.read(PATH_CONFIG_FILE)
CLOUD_URL = CONFIGS["CLOUD_API"]["url"]
CLOUD_URL_DEV = CONFIGS["CLOUD_API"]["url_dev"]
# from ldatastore import Datastore


def check_ssl():
    return os.path.isfile( CONFIGS["SSL"]["KEY"] ) and os.path.isfile(CONFIGS["SSL"]["CRT"])


def cloudAcquireUserInfo(auth_key, _id):
    try:
        cloud_url_acquire_platforms = f"{CLOUD_URL}/users/profiles/info"
        request=None

        if check_ssl():
            request = requests.post(cloud_url_acquire_platforms, json={"auth_key":auth_key, "id":_id}, cert=(CONFIGS["SSL"]["CRT"], CONFIGS["SSL"]["KEY"]))

        else:
            request = requests.post(cloud_url_acquire_platforms, json={"auth_key":auth_key, "id":_id})
        # print(request.text)
    except Exception as error:
        raise Exception(error)
    else:
        return request.json()

def cloudAcquireGrantLevelHashes(sessionId):
    datastore = Datastore()
    user_id = datastore.acquireUserFromId(sessionId)
    if not len(user_id) > 0 or not 'user_id' in user_id[0]:
        raise Exception("error fetching user id")

    user_id = user_id[0]['user_id']
    try:
        cloud_url_acquire_hash = f"{CLOUD_URL_DEV}/locals/users/hash1"
        print(">> CLOUD_URL: ", cloud_url_acquire_hash)
        request=None

        if check_ssl():
            # print("[+] going ssl...")
            request = requests.post(cloud_url_acquire_hash, json={"id":user_id}, cert=(CONFIGS["SSL"]["CRT"], CONFIGS["SSL"]["KEY"]))

        else:
            request = requests.post(cloud_url_acquire_hash, json={"id":user_id})
    except Exception as error:
        raise Exception(error)
    else:
        print(request)
        return request.json()


def cloudAcquireUserPlatforms(session_id, phonenumber):
    datastore = Datastore()
    auth_key = cloudGetUserAuthKey(phonenumber)
    print(auth_key)
    if not 'auth_key' in auth_key:
        raise Exception('auth key not acquired')

    auth_key = auth_key['auth_key']
    try:
        cloud_url_acquire_platforms = f"{CLOUD_URL}/users/providers"
        request=None

        if check_ssl():
            # print("[+] going ssl...")
            request = requests.post(cloud_url_acquire_platforms, json={"auth_key":auth_key}, cert=(CONFIGS["SSL"]["CRT"], CONFIGS["SSL"]["KEY"]))

        else:
            request = requests.post(cloud_url_acquire_platforms, json={"auth_key":auth_key})
        # print(request.text)
    except Exception as error:
        raise Exception(error)
    else:
        return request.json()

def cloudGetUserAuthKey(phonenumber):
    try:
        cloud_url_auth_users = f"{CLOUD_URL_DEV}/users/profiles"
        # print(">> CLOUD_URL: ", cloud_url_auth_users)
        request=None

        if check_ssl():
            # print("[+] going ssl...")
            request = requests.post(cloud_url_auth_users, json={"phone_number":phonenumber}, cert=(CONFIGS["SSL"]["CRT"], CONFIGS["SSL"]["KEY"]))
        else:
            request = requests.post(cloud_url_auth_users, json={"phone_number":phonenumber})
    except Exception as error:
        raise Exception(error)
    else:
        return request.json()

def cloudAuthUser(platform, protocol, phonenumber):
    request = cloudGetUserAuthKey(phonenumber)
    if not "status_code" in request and request.status_code != 200:
        return None
    if not "auth_key" in request:
        return None
    else:
        # print("[+] User authenticated... Fetching tokens:", platform)
        # with everything authenticated, let's get the tokens

        cloud_url_auth_users = CLOUD_URL + "/users/stored_tokens"
        # print(">> CLOUD_URL: ", cloud_url_auth_users)
        # request = requests.post(cloud_url_auth_users, json={"auth_key":request["auth_key"]})
        if check_ssl():
            request = requests.post(cloud_url_auth_users, json={"auth_key":request["auth_key"], "platform":platform}, cert=(CONFIGS["SSL"]["CRT"], CONFIGS["SSL"]["KEY"]))
        else:
            request = requests.post(cloud_url_auth_users, json={"auth_key":request["auth_key"], "platform":platform})

        if not "status_code" in request and request.status_code != 200:
            return None
        
        req_json = request.json()
        # print("text:", req_json)

        if len(req_json) > 0:
            return req_json

        return None
