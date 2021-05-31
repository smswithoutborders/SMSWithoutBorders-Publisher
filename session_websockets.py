#!/usr/bin/python

# WS server that sends messages at random intervals

import asyncio
import datetime
import random
import websockets
import uuid

class c_websocket:
    state = 'run'
    def __init__(self, websocket):
        self.websocket = websocket
        # self.state = 'run'

    def get_socket(self):
        return self.websocket

connected = {}
async def time(websocket, path):
    print("[+] New client:", websocket, path)
    print(type(websocket))
    if path == '/sync/sessions':
        try:
            iterator = 0
            session_id = _id=uuid.uuid4().hex

            soc = c_websocket(websocket)
            connected[session_id] = soc
            while iterator < 4 and connected[session_id].state == 'run':
                url_data = f'{path}/{session_id}'
                await connected[session_id].get_socket().send(url_data)
                await asyncio.sleep(15)
                iterator+=1

                session_id = _id=uuid.uuid4().hex
                connected[session_id] = websocket
            print("[-] Socket ended..")
        except Exception as error:
            print(error)
            print(websocket)

    if path.find('/sync/ack') > -1:
        session_id = path.split('/')[3]
        print(session_id)
        connected[session_id].state = 'ack'
        await connected[session_id].get_socket().send("acked...")
        del connected[session_id]

ip_address = "0.0.0.0"
# ip_address = "127.0.0.1"
start_server = websockets.serve(time, ip_address, 5678)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
