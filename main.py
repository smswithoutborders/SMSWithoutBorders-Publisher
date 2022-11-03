#!/usr/bin/env python3

from flask import Flask, request, jsonify
from flask_cors import CORS

import logging
import requests
import json
import os, sys

app = Flask(__name__)

@app.route('/publish', methods=['POST'])
def publish():
    """
    - Expecting a JSON request.
    """

    try:
        data = request.json
    except Exception as error:
        return '', 500

    else:
        if not 'message' in data or not 'MSISDN' in data:
            return 'poorly formed json', 400

        message = data['message']
        MSISDN = data['MSISDN']

        app.logger.debug("Message for publishing: %s", message)
        try:
            request_publishing(MSISDN=MSISDN, data=message)
        except Exception as error:
            app.logger.exception(error)
            return '', 500

    return '', 200


def request_publishing(MSISDN: str, data: str)->None:
    """
    TODO:
        - Figure out if platform exist in the first place
    """
    platform_letter = data.split(':')[0]
    platform = Platform.get_platform_from_letter(platform_letter)

    if not platform:
        """
        Return unknown platform exception
        """
    try:
        data = ':'.join(data.split(':')[1:])
        publish(platform, data)
    except Exception as error:
        raise error


def publish(platform, data: str) -> None:
    """
    """
    try:
        platform.publish(data)
    except Exception as error:
        raise error
    else:
        logger.info("Published successfully...")


if __name__ == "__main__":
    """
    """
    host = "127.0.0.1"
    port = 13000
    debug = True

    app.run(host=host, port=port, debug=debug, threaded=True )
