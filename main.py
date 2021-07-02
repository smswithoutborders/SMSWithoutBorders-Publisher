#!/usr/bin/python3

'''
- when qr expires should not be used again
- when qr is synced cannot be used again
- if sync with same phonenumber, replace previous sync with new one
'''
import os
import sys
import configparser
import traceback
import asyncio
import websocket
import requests
import ssl
import uuid

from twilio.rest import Client
import src.cloudfunctions as cloudfunctions
import src.sync_accounts as sync_accounts
import src.routerfunctions as routerfunctions

import start_routines
import src.deduce_isp as isp

from platforms import Platforms
from src.securitylayer import SecurityLayer

from base64 import b64decode,b64encode
import json

from flask import Flask, request, jsonify
from flask_cors import CORS

start_routines.sr_database_checks()
app = Flask(__name__)
CORS(app)

CONFIGS = configparser.ConfigParser(interpolation=None)

PATH_CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'configs', 'config.router.ini')
CONFIGS.read(PATH_CONFIG_FILE)

from src.datastore import Datastore

twilio_service=None
twilio_client = None
if CONFIGS['TWILIO']['ACCOUNT_SID'] != None and CONFIGS['TWILIO']['AUTH_TOKEN'] != None:
    account_sid = CONFIGS['TWILIO']['ACCOUNT_SID']
    auth_token = CONFIGS['TWILIO']['AUTH_TOKEN']
    twilio_client = Client(account_sid, auth_token)
    twilio_service = twilio_client.verify.services.create( friendly_name=CONFIGS['TWILIO']['FRIENDLY_NAME'])
    # print(twilio_service.sid)

def socket_message_error(wsapp, err):
    print(err)

def socket_message(session_id, message):
    # websocket.enableTrace(True)
    # TODO make certificates actually do something
    ssl_context=None
    if os.path.exists(CONFIGS["SSL"]["CRT"]) and os.path.exists(CONFIGS["SSL"]["KEY"]) and os.path.exists(CONFIGS["SSL"]["PEM"]):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=CONFIGS['SSL']['CRT'], keyfile=CONFIGS['SSL']['KEY'])
    if message == 'ack':
        # uri= f"ws://localhost:{CONFIGS['WEBSOCKET']['PORT']}/sync/ack/{session_id}"
        uri= f"{CONFIGS['WEBSOCKET']['URL']}:{CONFIGS['WEBSOCKET']['PORT']}/sync/ack/{session_id}"
        print(uri)
        ws = websocket.WebSocketApp(uri, on_error=socket_message_error) 
        if not ssl_context == None:
            ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
        else:
            ws.run_forever()

    elif message == 'pause':
        uri= f"{CONFIGS['WEBSOCKET']['URL']}:{CONFIGS['WEBSOCKET']['PORT']}/sync/pause/{session_id}"
        print(uri)
        ws = websocket.WebSocketApp(uri, on_error=socket_message_error)
        if not ssl_context == None:
            ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
        else:
            ws.run_forever()

    else:
        print( "unknown socket protocol requested" )

def acquire_requester(phonenumber):
    datastore = Datastore()
    try:
        return sync_accounts.acquire_user_from_phonenumber(phonenumber)
    except Exception as error:
        raise Exception(error)

@app.route('/', methods=['GET'])
def index():
    return "May the force be with you!"


@app.route('/sync/sessions', methods=['POST', 'GET'])
def sessions():
    if request.method == 'POST':
        request_body = request.json
        if not 'auth_key' in request_body or len(request_body['auth_key']) < 1:
            return jsonify({"message":"No auth key found"}), 400
        if not 'id' in request_body or len(request_body['id']) < 1:
            return jsonify({"message":"No id found"}), 400

        user_authkey = request_body['auth_key']
        user_id = request_body['id']
        try: 
            user_details = cloudfunctions.cloudAcquireUserInfo(user_authkey, user_id)
            
            if not 'phonenumber_hash' in user_details or not 'id' in user_details:
                return jsonify({"message":"User may not exist"}), 403
            session_id = sync_accounts.new_session(country_code=user_details["country_code"], phonenumber=user_details["phonenumber_hash"], user_id=user_details["id"])

            session_url = f"{CONFIGS['WEBSOCKET']['URL']}:{CONFIGS['WEBSOCKET']['PORT']}/sync/sessions/{session_id}"
            # print(f"origin url: {origin_url}")
            # session_url = f"ws://{origin_url}/sync/sessions/{session_id}"

            print(session_url)
            return jsonify({"url":session_url}), 200
        except Exception as error:
            print(traceback.format_exc())

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
        # sid = session_id
        ret_value = {"pk":gateway_publicKey, "sk":sharedKey, "pd":passwd, "pl":platforms, "ph":phonenumbers, "sid":session_id}
        socket_message(session_id=session_id, message='ack')

        prev_session = session_id
        session_id = uuid.uuid4().hex
        response = requests.get(f"{CONFIGS['CLOUD_API']['URL']}:{CONFIGS['API']['PORT']}/sync/sessions?prev_session_id={prev_session}&session_id={session_id}")

        return jsonify(ret_value)
    except Exception as error:
        print(traceback.format_exc())
        return jsonify({"status":500, "message":"internal error"})


@app.route('/twilio_messages', methods=['POST'])
def incoming_messages():
    print(request.values)
    From=request.values.get('From', None)
    To=request.values.get('To', None)
    FromCountry=request.values.get('FromCountry', None)
    NumSegments=request.values.get('NumSegments', None)
    Body=request.values.get('Body',None)

    print(f"From: {From}\nTo: {To}\nBody: {Body}\nFromCountry: {FromCountry}\nNumSegments: {NumSegments}")
    '''
    try:
        router_url = CONFIGS["CLOUD_API"]["url"]
        print(f"[+] Router url: {router_url}")
        api_request=requests.post(f"{router_url}/messages", json={"text":Body, "phonenumber":From})
    except Exception as error:
        print( error )
    else:
        print( api_request.text )
    
    return api_request.text
    '''
    forward = {}
    forward["phonenumber"] = From
    forward["text"] = Body
    forward["From"] = "Twilio"

    # return new_messages(forward)
    
    response=new_messages(forward)
    # print(f"- router response: {response.text}")
    return ""

@app.route('/messages', methods=['POST', 'GET'])
def new_messages(forwarded=None):
    request_body = None
    if forwarded is not None:
        request_body = forwarded
    elif request.method == 'POST':
        request_body = request.json

    if request_body is None:
        return jsonify({"status":401, "message":"invalid request, missing body"})
    if not 'text' in request_body:
        return jsonify({"status":400, "message":"missing text"})

    if not 'phonenumber' in request_body:
        return jsonify({"status":400, "message":"missing phonenumber"})

    text = request_body["text"]
    phonenumber = request_body["phonenumber"]
    # phonenumber = isp.rm_country_code(phonenumber)
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
        print(traceback.format_exc())
        return_json["body"] = str(err)
    
    return jsonify(return_json)


def twilio_send(number):
    # client = Client(account_sid, auth_token)
    verification = twilio_client.verify \
            .services(twilio_service.sid) \
            .verifications \
            .create(to=number, channel='sms')

    # print(verification.status)
    # print(verification)

    if verification.status == 'pending':
        return twilio_service.sid
    return None

def twilio_sms_send(number, text):
    # client = Client(account_sid, auth_token)

    try:
        messages = twilio_client.messages.create(
                from_=CONFIGS['TWILIO']['OWN_NUMBER'],
                body=text,
                # status_callback=CONFIGS['TWILIO']['ON_DELIVERY'],
                to=number
            )

    except Exception as error:
        raise Exception( error )
    else:
        # print(messages.sid)
        return messages.sid

    return None


def twilio_verify(number, code, twilio_service_sid=None):
    service_code = None
    if twilio_service_sid is not None:
        service_code = twilio_service_sid
    else:
        service_code = twilio_service.sid

    try:
        verification_check = twilio_client.verify \
                .services(service_code) \
                .verification_checks \
                .create(to=number, code=code)

        # print(verification.status)
        # print(verification_check)

        return verification_check.status
    except Exception as error:
        raise Exception(error)

@app.route('/sms/twilio/plain', methods=['POST'])
def sms_twilio_send():
    # generate code
    # connect to twilio and send to number (number required)
    '''
    if request.remote_addr != '127.0.0.1':
        return '', 403
    '''
    request_body=None
    if request.method == 'POST':
        request_body = request.json
    if not 'number' in request_body:
        return jsonify({"message":"sending number required"}), 400
    if not 'text' in request_body:
        return jsonify({"message":"sending text required"}), 400

    number = request_body['number']
    text = request_body['text']
    try:
        message_sid = twilio_sms_send(number=number, text=text)
    except Exception as error:
        print(error)
    else:
        if message_sid is not None:
            return jsonify({"message_sid":message_sid}), 200

    return jsonify({"message":"failed"}), 500


@app.route('/sms/twilio', methods=['POST'])
def sms_twilio():
    # generate code
    # connect to twilio and send to number (number required)
    '''
    if request.remote_addr != '127.0.0.1':
        return '', 403
    '''
    request_body=None
    if request.method == 'POST':
        request_body = request.json
    if not 'number' in request_body:
        return jsonify({"message":"sending number required"}), 400

    number = request_body['number']
    service_sid = twilio_send(number)
    
    if service_sid is not None:
        return jsonify({"service_sid":service_sid}), 200

    return jsonify({"message":"failed"}), 500

@app.route('/sms/twilio/verification_token', methods=['POST'])
def sms_twilio_verify():
    # generate code
    # connect to twilio and send to number (number required)
    '''
    if request.remote_addr != '127.0.0.1':
        return '', 403
    '''
    request_body=None
    if request.method == 'POST':
        request_body = request.json
    if not 'number' in request_body:
        return jsonify({"message":"number required"}), 400
    if not 'code' in request_body:
        return jsonify({"message":"code required"}), 400
    if not 'session_id' in request_body:
        return jsonify({"message":"session id required"}), 400

    number = request_body['number']
    code = request_body['code']
    session_id = request_body['session_id']

    try:
        status = twilio_verify(number, code, session_id)
    except Exception as error:
        return jsonify({"message":"failed"}), 500
    else:
        if status is not None:
            # status=('approved' || 'pending')
            return jsonify({"verification_status":status}), 200

    return jsonify({"message":"failed"}), 500


# print_ip()
if __name__ == '__main__':
    if len(sys.argv) == 1:
        '''
        if CONFIGS["API"]["DEBUG"] == "1":
            # Allows server reload once code changes
            app.debug = True
        '''

        if os.path.exists(CONFIGS["SSL"]["CRT"]) and os.path.exists(CONFIGS["SSL"]["KEY"]) and os.path.exists(CONFIGS["SSL"]["PEM"]):
            # ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            # ssl_context.load_verify_locations(CONFIGS["SSL"]["PEM"])
            print("- Running secured...")
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            ssl_context.load_cert_chain(CONFIGS["SSL"]["CRT"], CONFIGS["SSL"]["KEY"])
            app.run(ssl_context=ssl_context, host=CONFIGS["API"]["HOST"], port=CONFIGS["API"]["PORT"], debug=app.debug, threaded=True )
        else:
            print("- Running insecure...")
            app.run(host=CONFIGS["API"]["HOST"], port=CONFIGS["API"]["PORT"], debug=app.debug, threaded=True )


    else:
        if sys.argv[1] == '-twilio_auth_send':
            # ('number')
            print(twilio_send(sys.argv[2]))
        elif sys.argv[1] == '-twilio_verify':
            # ('service.sid', 'number', 'code')
            try:
                print(twilio_verify(twilio_service_sid=sys.argv[2], number=sys.argv[3], code=sys.argv[4]))
            except Exception as error:
                print("Exception happened... guess why")
        elif sys.argv[1] == '-twilio_send':
            # ('service.sid', 'number', 'code')
            try:
                print(twilio_sms_send(number=sys.argv[2], text=sys.argv[3]))
            except Exception as error:
                print(error)
                print("Exception happened... guess why")
