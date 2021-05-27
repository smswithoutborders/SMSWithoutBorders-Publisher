#!/usr/bin/python

# WS server that sends messages at random intervals

import asyncio
import datetime
import random
import websockets

connected = set()
async def time(websocket, path):
    print("[+] New client:", websocket, path)
    connected.add(websocket)
    while True:
        now = datetime.datetime.utcnow().isoformat() + "Z"
        await websocket.send(now)
        await asyncio.sleep(random.random() * 3)


ip_address = "0.0.0.0"
# ip_address = "127.0.0.1"
start_server = websockets.serve(time, ip_address, 5678)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
