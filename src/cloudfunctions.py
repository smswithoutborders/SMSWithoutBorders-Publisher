#!/bin/python


import configparser
import requests
CONFIGS = configparser.ConfigParser(interpolation=None)

CONFIGS.read("config.router.ini")
CLOUD_URL = CONFIGS["CLOUD_API"]["url"]
# from ldatastore import Datastore


def cloudAuthUser(platform, protocol, phonenumber):
    try:
        cloud_url_auth_users = f"{CLOUD_URL}/users/profiles"
        print(">> CLOUD_URL: ", cloud_url_auth_users)
        request = requests.post(cloud_url_auth_users, json={"platform":platform, "protocol":protocol, "phone_number":phonenumber})
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
            
            print("[+] User authenticated... Fetching tokens")
            # with everything authenticated, let's get the tokens

            cloud_url_auth_users = CLOUD_URL + "/users/stored_tokens"
            print(">> CLOUD_URL: ", cloud_url_auth_users)
            # request = requests.post(cloud_url_auth_users, json={"auth_key":request["auth_key"]})
            request = requests.post(cloud_url_auth_users, json={"auth_key":request["auth_key"], "platform":platform})

            if not "status_code" in request and request.status_code is not 200:
                return None
            
            req_json = request.json()
            print("text:", req_json)

            if len(req_json) > 0:
                return req_json

            return None
