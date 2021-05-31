#!/usr/bin/python

# WS server that sends messages at random intervals

import asyncio
import datetime
import random
import websockets
import uuid
import configparser
import os
import requests

CONFIGS = configparser.ConfigParser(interpolation=None)

PATH_CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'configs', 'config.router.ini')
CONFIGS.read(PATH_CONFIG_FILE)

class c_websocket:
    state = 'run'
    def __init__(self, websocket):
        self.websocket = websocket
        # self.state = 'run'

    def get_socket(self):
        return self.websocket

connected = {}
async def sessions(websocket, path):
    print("[+] New client:", websocket, path)
    print(f'# Clients: {len(connected)}')
    if path.find('sync/sessions') > -1:
        path= path.split('/')
        s_path = path[1] + '/' + path[2]
        session_id = path[3]
        # print("[+] s_path:", s_path)
        # print("[+] session_id:", session_id)
        api_url = CONFIGS['API']['HOST']
        api_port = CONFIGS['API']['PORT']
        protocol = "http"
        try:
            iterator = 0
            soc = c_websocket(websocket)
            if session_id in connected:
                print('>> stoping connection, client exist')
                return
            connected[session_id] = soc

            import socket
            h_name = socket.gethostname()
            IP_address = socket.gethostbyname(h_name)
            while iterator < 3 and connected[session_id].state == 'run':
                url_data = f'{protocol}://{IP_address}:{api_port}/sync/sessions/{session_id}'
                await connected[session_id].get_socket().send(url_data)
                await asyncio.sleep(15)
                iterator+=1

                prev_session=session_id
                session_id = _id=uuid.uuid4().hex
                request = requests.get(f"http://localhost:{CONFIGS['API']['PORT']}/sync/sessions?prev_session_id={prev_session}&session_id={session_id}")
                # TODO: check if request has been made
                connected[session_id] = soc
            del connected[session_id]
            print("[-] Socket ended..")
        except Exception as error:
            print(error)
            print(websocket)

    elif path.find('/sync/ack') > -1:
        print(">> acknowledgment seen...")
        session_id = path.split('/')[3]
        connected[session_id].state = 'ack'
        await connected[session_id].get_socket().send("200- acked")
        del connected[session_id]

server_ip = CONFIGS['API']['HOST']
server_port = CONFIGS['WEBSOCKET']['PORT']
print(f"ws://{server_ip}:{server_port}")
start_server = websockets.serve(sessions, server_ip, server_port)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
