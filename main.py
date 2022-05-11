#!/usr/bin/env python3

import logging
import requests

def dev_backend_authenticate_user(auth_id: str, auth_key: str) -> tuple:
    """
    """


    dev_backend_api_auth_url = "https://developers.smswithoutborders.com:13000/v1/authenticate"
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

    backend_publisher_api_decrypted_tokens_request_url = "http://localhost:10000/v1/decrypt"

    response = request.get(
            backend_publisher_api_decrypted_tokens_request_url,
            json={"platform": platform, "phone_number": MSISDN})

    response.raise_for_status()

    return response.json()


if __name__ == "__main__":
    """
    TODO:
    - Authenticate with Dev Backend.
    - Make the request for decrypted tokens.
    """

    logging.basicConfig(level='DEBUG')

    auth_id = ""
    auth_key = ""
    MSISDN = "+"
    platform = ""

    try:
        authenticated_user, request = dev_backend_authenticate_user(
                auth_id = auth_id, auth_key = auth_key)
    except Exception as error:
        logging.exception(error)
    else:
        logging.debug("%s %s", authenticated_user, request)
        decrypted_tokens = backend_publisher_api_request_decrypted_tokens(
                request=request, MSISDN=MSISDN, platform=platform)

        logging.debug("Decrypted tokens: %s", decrypted_tokens)
