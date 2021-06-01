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

def cloudAcquireGrantLevelHashes(user_id):
    datastore = Datastore()
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


def cloudAcquireUserPlatforms(user_id):
    datastore = Datastore()
    auth_key = cloudGetUserAuthKey(user_id)
    print("auth_key:", auth_key)
    if not 'auth_key' in auth_key:
        raise Exception("no auth key found")

    try:
        cloud_url_acquire_platforms = f"{CLOUD_URL}/users/providers"
        request=None

        if check_ssl():
            # print("[+] going ssl...")
            request = requests.post(cloud_url_acquire_platforms, json={"auth_key":auth_key['auth_key'], "id":user_id}, cert=(CONFIGS["SSL"]["CRT"], CONFIGS["SSL"]["KEY"]))

        else:
            request = requests.post(cloud_url_acquire_platforms, json={"auth_key":auth_key['auth_key'], "id":user_id})
        # print(request.text)
    except Exception as error:
        raise Exception(error)
    else:
        return request.json()

def cloudGetUserAuthKey(user_id):
    print("user_id:", user_id)
    try:
        cloud_url_auth_users = f"{CLOUD_URL_DEV}/users/profiles"
        # print(">> CLOUD_URL: ", cloud_url_auth_users)
        request=None

        if check_ssl():
            # print("[+] going ssl...")
            request = requests.post(cloud_url_auth_users, json={"id":user_id}, cert=(CONFIGS["SSL"]["CRT"], CONFIGS["SSL"]["KEY"]))
        else:
            request = requests.post(cloud_url_auth_users, json={"id":user_id})
    except Exception as error:
        raise Exception(error)
    else:
        return request.json()

def cloudAuthUser(user_id, provider, platform, protocol, phonenumber):
    request = cloudGetUserAuthKey(user_id)
    if not "auth_key" in request:
        return None
    else:
        cloud_url_auth_users = CLOUD_URL + "/users/stored_tokens"
        if check_ssl():
            request = requests.post(cloud_url_auth_users, json={"id":user_id, "auth_key":request["auth_key"],"provider":provider, "platform":platform}, cert=(CONFIGS["SSL"]["CRT"], CONFIGS["SSL"]["KEY"]))
        else:
            request = requests.post(cloud_url_auth_users, json={"id":user_id, "auth_key":request["auth_key"],"provider":provider, "platform":platform})

    return request.json()
