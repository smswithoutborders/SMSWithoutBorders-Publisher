#!/usr/bin/env python3

from flask import Flask, request, jsonify
from flask_cors import CORS

import logging
import requests
import json
import os
import sys
import configparser

config_file_filepath = os.path.join(
        os.path.dirname(__file__), 'configs', 'config.ini')

__config = configparser.ConfigParser()
__config.read(config_file_filepath)

app = Flask(__name__)
# TODO Add origins to config file
CORS(
    app,
    origins="*",
    supports_credentials=True,
)

@app.route('/publish', methods=['POST'])
def publish():
    """
    Expecting a JSON request.
    """
    try:
        data = request.json
    except Exception as error:
        return '', 500
    else:
        message = data['message']
        app.logger.debug("Message for publishing: %s", message)


def dev_backend_authenticate_user(auth_id: str, auth_key: str) -> tuple:
    """
    """
    dev_backend_api_auth_url = __config['DEV_API']['AUTHENTICATION_URL']
    logging.debug("dev_backed_api_auth_url: %s", dev_backend_authenticate_user)

    request = requests.Session()
    response = request.post(
            dev_backend_api_auth_url,
            json={"auth_key": auth_key, "auth_id": auth_id})

    response.raise_for_status()


    return True, request


def backend_publisher_api_request_decrypted_tokens(
        request: requests.Session, MSISDN: str, platform: str) -> dict:
    """Request for the user's tokens.

    Args:
        Request (requests.Session): authenticated sessions from dev BE.

        MSISDN (str): phone number of the user token is requested for.

    Returns:
        json_response (dict)
    """

    backend_publisher_port = int(__config['BACKEND_PUBLISHER']['PORT'])
    backend_publisher_endpoint = __config['BACKEND_PUBLISHER']['ENDPOINT']
    backend_publisher_api_decrypted_tokens_request_url = "http://localhost:%d%s" % (
            backend_publisher_port, backend_publisher_endpoint)

    # logging.debug("Cookies: %s\n", request.cookies, dir(request.cookies))
    # logging.debug("Cookies: %s\n", dir(request.cookies))
    logging.debug("Cookies: %s\n", request.cookies.get_dict())

    cookies=json.dumps(request.cookies.get("SWOBDev"))
    cookies = {"SOWBDev":cookies}
    logging.debug(cookies)
    response = request.post(
            backend_publisher_api_decrypted_tokens_request_url,
            json={"platform": platform, "phone_number": MSISDN}, cookies=request.cookies.get_dict())
    """
    response = request.post(
            backend_publisher_api_decrypted_tokens_request_url,
            json={"platform": platform, "phone_number": MSISDN})
    """

    response.raise_for_status()

    return response.json()


def request_publishing(MSISDN: str, platform: str)->None:
    """
    """

    auth_key = __config['DEV_API']['AUTH_KEY']
    auth_id = __config['DEV_API']['AUTH_ID']

    logging.debug("Auth key: %s", auth_key)
    logging.debug("Auth id: %s", auth_id)

    try:
        authenticated_user, request = dev_backend_authenticate_user(
                auth_id = auth_id, auth_key = auth_key)
    except Exception as error:
        logging.exception(error)
    else:
        logging.debug("%s %s", authenticated_user, request.cookies)
        decrypted_tokens = backend_publisher_api_request_decrypted_tokens(
                request=request, MSISDN=MSISDN, platform=platform)

        logging.debug("Decrypted tokens: %s", decrypted_tokens)


if __name__ == "__main__":
    """
    TODO:
    - Authenticate with Dev Backend.
    - Make the request for decrypted tokens.
    """

    logging.basicConfig(level='DEBUG')

    MSISDN = sys.argv[1]
    platform = sys.argv[2]
    request_publishing(MSISDN=MSISDN, platform=platform)

