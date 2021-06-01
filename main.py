#!/usr/bin/python

import os
import configparser
import traceback
import asyncio
import websocket

import src.cloudfunctions as cloudfunctions
import src.sync_accounts as sync_accounts
import src.routerfunctions as routerfunctions

import start_routines
import src.deduce_isp as isp

from src.platforms import Platforms
from src.securitylayer import SecurityLayer

from base64 import b64decode,b64encode
import json

CONFIGS = configparser.ConfigParser(interpolation=None)

PATH_CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'configs', 'config.router.ini')
CONFIGS.read(PATH_CONFIG_FILE)

from src.datastore import Datastore

from flask import Flask, request, jsonify
from flask_cors import CORS
app = Flask(__name__)
CORS(app)

def socket_message(session_id, message):
    if message == 'ack':
        uri= f"ws://localhost:{CONFIGS['WEBSOCKET']['PORT']}/sync/ack/{session_id}"
        ws = websocket.WebSocketApp(uri)
        ws.run_forever()

    elif message == 'pause':
        uri= f"ws://localhost:{CONFIGS['WEBSOCKET']['PORT']}/sync/pause/{session_id}"
        ws = websocket.WebSocketApp(uri)
        ws.run_forever()

    else:
        print( "unknown socket protocol requested" )

def acquire_requester(phonenumber):
    datastore = Datastore()
    try:
        return sync_accounts.acquire_user_from_phonenumber(phonenumber)
    except Exception as error:
        raise Exception(error)


@app.route('/sync/sessions', methods=['POST', 'GET'])
def sessions():
    if request.method == 'POST':
        request_body = request.json
        if not 'auth_key' in request_body or len(request_body['auth_key']) < 1:
            return jsonify({"status":403, "message":"No auth key found"})
        if not 'id' in request_body or len(request_body['id']) < 1:
            return jsonify({"status":403, "message":"No id found"})

        user_authkey = request_body['auth_key']
        user_id = request_body['id']
        user_details = cloudfunctions.cloudAcquireUserInfo(user_authkey, user_id)
        if not 'phone_number' in user_details or not 'id' in user_details:
            return jsonify({"status":403, "message":"User may not exist"})
        session_id = sync_accounts.new_session(phonenumber=user_details["phone_number"], user_id=user_details["id"])

        # print(request.environ)
        origin_url = request.environ['REMOTE_ADDR'] + ":" + CONFIGS['WEBSOCKET']['PORT']
        session_url = f"ws://{origin_url}/sync/sessions/{session_id}"
        print(session_url)
        return jsonify({"status": 200, "url":session_url})

    elif request.method == 'GET':
        prev_session_id = request.args.get('prev_session_id')
        session_id = request.args.get('session_id')
        print(f"- Trying to update: {prev_session_id} -> {session_id}")
        try:
            results= sync_accounts.update_session(prev_session_id=prev_session_id, session_id=session_id)
            return '200- done'
        except Exception as error:
            return error
    

@app.route('/sync/sessions/<session_id>', methods=['POST'])
def sync(session_id):
    user_info = sync_accounts.acquire_sessions(session_id)
    if len(user_info) < 1:
        return jsonify({"status":403, "message":"session not found"})
    if not "user_id" in user_info[0]:
        return jsonify({"status":500, "message":"internal system error"})
    socket_message(session_id=session_id, message='pause')

    securityLayer = SecurityLayer()
    request_body = request.json
    if not 'public_key' in request_body:
        return jsonify({"status":403, "message":"No public key"})

    user_publicKey = request_body['public_key']
    gateway_publicKey = securityLayer.get_public_key()
    sharedKey = securityLayer.get_shared_key()
    sync_accounts.store_credentials( shared_key=sharedKey, public_key=user_publicKey, session_id=session_id)
    sharedKey = securityLayer.rsa_encrypt(data=sharedKey, key=user_publicKey)
    sharedKey = str(b64encode(sharedKey), 'utf-8')

    # sha512 asshole
    # passwd = "F50C51ED2315DCF3FA88181CF033F8029CAC64F7DEA4048327CA032EC102EA74"
    try:
        passwd = cloudfunctions.cloudAcquireGrantLevelHashes(user_info[0]["user_id"])
        if not 'password_hash' in passwd:
            return jsonify({"status":403, "message":"Error acquiring password hash"})

        passwd = passwd['password_hash']
        passwd = securityLayer.rsa_encrypt(data=passwd, key=user_publicKey)
        passwd = str(b64encode(passwd), 'utf-8')

        platforms = cloudfunctions.cloudAcquireUserPlatforms(user_id=user_info[0]["user_id"])
        print(platforms)
        if not 'user_provider' in platforms:
            return jsonify({"status":403, "message":"Error fetching platforms"})
        # platforms = [str(b64encode(securityLayer.rsa_encrypt(data=platforms[i], key=user_publicKey), 'utf-8')) for i in platforms]

        phonenumbers = []
        # TODO: determine default ISP from user's phonenumber
        with open(os.path.join(os.path.dirname(__file__), 'configs', 'isp.json')) as isp_config:
            isp_config = json.load(isp_config)

            for isp in isp_config:
                phonenumbers.append( isp )

        # print(phonenumbers)
        # pk = public key
        # sk = shared key
        # pd = password
        # pl = platforms
        # ph = phonenumbers
        ret_value = {"pk":gateway_publicKey, "sk":sharedKey, "pd":passwd, "pl":platforms, "ph":phonenumbers}
        socket_message(session_id=session_id, message='ack')
        return jsonify(ret_value)
    except Exception as error:
        print(traceback.format_exc())
        return jsonify({"status":500, "message":"internal error"})

@app.route('/messages', methods=['POST', 'GET'])
def new_messages():
    if request.method == 'POST':
        request_body = request.json
        if request_body is None:
            return jsonify({"status":401, "message":"invalid request, missing body"})
        if not 'text' in request_body:
            return jsonify({"status":400, "message":"missing text"})

        if not 'phonenumber' in request_body:
            return jsonify({"status":400, "message":"missing phonenumber"})

        text = request_body["text"]
        phonenumber = request_body["phonenumber"]
        phonenumber = isp.rm_country_code(phonenumber)
        timestamp=""
        discharge_timestamp=""
        if "timestamp" in request_body:
            timestamp = request_body["timestamp"]
        if "discharge_timestamp" in request_body:
            discharge_timestamp = request_body["discharge_timestamp"]

        print(f"{phonenumber}|{text}")

        return_json = {"status" :"", "body":""}
        try: 
            user_details = acquire_requester(phonenumber)
            # authenticate request
            if len(user_details) < 1:
                return jsonify({"status":401, "message":"requester not synced"})

            print("[+] - User authenticated")
            messageID=None

            # parse the contents of the SMS message
            # print(user_details)
            h_password = cloudfunctions.cloudAcquireGrantLevelHashes(user_details[0]['user_id'])
            if not 'password_hash' in h_password:
                return jsonify({"status":403, "message":"failed to get required hashes"})

            user_details[0]["password_hash"] = h_password
            parsedText = routerfunctions.routerParseText(text, user_details[0])
            print(f">> ParsedText: {parsedText}")

            # check for a valid protocol being returned
            if parsedText is not None and "protocol" in parsedText:

                # Authenticate acquire stored stoken information for users
                userDetails = cloudfunctions.cloudAuthUser(user_id=user_details[0]['user_id'], phonenumber=phonenumber, protocol=parsedText["protocol"], platform=parsedText["platform"], provider=parsedText["provider"])
                # userDetails = cloudfunctions.cloudAuthUser("gmail", "send", phonenumber)

                if userDetails is not None:
                    if len(userDetails) > 0:
                        try:
                            # platform = Platforms("gmail")
                            platform = Platforms(platform=parsedText["platform"])
                            results = platform.execute(parsedText["protocol"], parsedText["body"], userDetails)
                        except Exception as error:
                            raise Exception(error)
                        else:
                            if results:
                                print(f"[+] Successfully executed for platform - {results}")
                                return_json["status"] = 200
                                return_json["body"] = f"successfully executed for platform - {results}"
                            else:
                                print(f"[+] Failed to execute for platform - {results}")
                                return_json["status"] = 500
                                return_json["body"] = results
                    else:
                        return_json["status"] = 404
                        raise Exception(f"no token stored in wallet")
                else:
                    return_json["status"] = 403
                    print(userDetails)
                    raise Exception(f"Failed to authenticate user/request...")
            else:
                return_json["status"] = 400
                raise Exception(f"Could not determine protocol in parsedText: {parsedText}")
                    
        except Exception as err:
            # return_json["status"] = request.status_code
            # return_json["status"] = 500
            # return_json["body"] = request
            print(err)
            return_json["body"] = str(err)
    
    return jsonify(return_json)

def print_ip():
    import socket
    h_name = socket.gethostname()
    IP_addres = socket.gethostbyname(h_name)
    print("Host Name is:" + h_name)
    print("Computer IP Address is:" + IP_addres)



if CONFIGS["API"]["DEBUG"] == "1":
    # Allows server reload once code changes
    app.debug = True

print_ip()
start_routines.sr_database_checks()
app.run(host=CONFIGS["API"]["HOST"], port=CONFIGS["API"]["PORT"], debug=app.debug, threaded=True )
