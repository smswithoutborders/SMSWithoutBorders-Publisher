#!/bin/python

import configparser
import cloudfunctions
import routerfunctions
import deduce_isp as isp

from platforms import Platforms
from securitylayer import SecurityLayer

CONFIGS = configparser.ConfigParser(interpolation=None)

CONFIGS.read("config.router.ini")
# from ldatastore import Datastore

from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/sync/sessions/<session_id>', methods=['POST'])
def sync(session_id):
    securityLayer = SecurityLayer()
    request_body = request.json
    user_publicKey = request_body['public_key']

    gateway_publicKey = securityLayer.get_public_key()
    sharedKey = securityLayer.get_shared_key()
    sharedKey = securityLayer.rsa_encrypt(data=sharedKey, key=user_publicKey)
    # passwd = datastore.get_password(session_id)
    passwd = "62BADBA41079EBB733A33124EDFE1F7947E798BC0C2715B60B3BB613A536F1813E0ED58042FBE60E8FE4D50D1C7D8E9C4518B07A97C764F9BB7808EB8C5002E3"
    passwd = securityLayer.rsa_encrypt(data=passwd, key=user_publicKey)

    return jsonify({"public_key":gateway_publicKey, "shared_key":str(sharedKey), "passwd":str(passwd)})

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
        
        # TODO: put logger in here to log everything
        print(f'''[+] New message...
                \n\t-text>> {text}
                \n\t-phonenumber>> {phonenumber}
                \n\t-timestamp>> {timestamp}
                \n\t-discharge_timestamp>> {discharge_timestamp}''')

        return_json = {"status" :"", "body":""}
        try: 
            # TODO: Determine ISP before sending messages
            messageID=None
            # messageID = datastore.new_message(text=text, phonenumber=phonenumber, isp="MTN", _type="sending")

            # parse the contents of the SMS message
            parsedText = routerfunctions.routerParseText(text)
            print(f">> ParsedText: {parsedText}")

            # check for a valid protocol being returned
            if parsedText is not None and "protocol" in parsedText:

                # Authenticate acquire stored stoken information for users
                userDetails = cloudfunctions.cloudAuthUser(phonenumber=phonenumber, protocol=parsedText["protocol"], platform=parsedText["platform"])
                # userDetails = cloudfunctions.cloudAuthUser("gmail", "send", phonenumber)

                if userDetails is not None:
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
                    return_json["status"] = 403
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
app.run(host=CONFIGS["API"]["HOST"], port=CONFIGS["API"]["PORT"], debug=app.debug )
