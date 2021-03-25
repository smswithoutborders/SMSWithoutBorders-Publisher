#!/bin/python

import configparser
import cloudfunctions
import routerfunctions

from platforms import Platforms

CONFIGS = configparser.ConfigParser(interpolation=None)

CONFIGS.read("config.router.ini")
# from ldatastore import Datastore

from flask import Flask, request, jsonify
app = Flask(__name__)

#datastore = Datastore(configs_filepath="libs/config.ini")
# datastore.get_datastore()
# datastore = Datastore(config=CONFIGS)

# Get current state of the daemon [idle, busy, help]
@app.route('/state')
def daemon_state():
    return "development"

@app.route('/messages', methods=['POST', 'GET'])
def new_messages():
    if request.method == 'POST':
        request_body = request.json
        print(request_body)
        if not 'text' in request_body:
            return jsonify({"status":400, "message":"missing text"})

        if not 'phonenumber' in request_body:
            return jsonify({"status":400, "message":"missing phonenumber"})

        text = request_body["text"]
        phonenumber = request_body["phonenumber"]
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
                print( userDetails )

                '''
                if userDetails is not None:
                    try:
                        # platform = Platforms("gmail")
                        platform = Platforms(platform=parsedText["platform"])
                        results = platform.execute(parsedText["protocol"], parsedText["body"], userDetails)
                    except Exception as error:
                        raise Exception(error)
                    else:
                        print("[+] Successfully executed for platform - {results}")
                        return_json["status"] = 200
                        return_json["body"] = results
                else:
                    raise Exception(f"Failed to authenticate user/request...")
                '''
            else:
                raise Exception(f"Could not determine protocol in parsedText: {parsedText}")
                    
        except Exception as err:
                return_json["status"] = request.status_code
                return_json["body"] = request
                return_json["error"] = err
    
    return jsonify(return_json)

if CONFIGS["API"]["DEBUG"] == "1":
    # Allows server reload once code changes
    app.debug = True

app.run(host=CONFIGS["API"]["HOST"], port=CONFIGS["API"]["PORT"], debug=app.debug )
