#!/bin/python


import configparser
import requests
CONFIGS = configparser.ConfigParser(interpolation=None)

CONFIGS.read("config.router.ini")
CLOUD_URL = CONFIGS["CLOUD_API"]["url"]
# from ldatastore import Datastore


def cloudAuthUser(platform, protocol, phonenumber):
    '''
    try:
        request = requests.post(CLOUD_URL, json={"platform":platform, "protocol":protocol, "phonenumber":phonenumber})
        if request.status_code is not 200:
            return None
    except Exception as error:
        raise Exception(error)
    else:
        return request.json()
    '''
    return True
