### Dependencies
- MySQL

### Features
\- Management of customized third-party service APIs \
\- Decrypts and utilizes saved user's third-party Oauth tokens 

### Getting Started
```bash
git submodule update --init --recursive
cp configs/example.config.mysql.ini configs/config.mysql.ini
cp configs/example.config.router.ini configs/config.router.ini
cp configs/example.isp.json configs/isp.json

# You can proceed to edit config files with the necessary credentials
# configs/isp.json -> the value for default is true is that isp would be the default number for the gateway
```

##### How to Run

__create venv__
```bash
python3 -m virtualenv .venv
```

__activate venv__
```bash
source .venv/bin/activate
```

__install requirements__
```bash
pip install -r requirements.txt
```

__start the API__
```bash
# start routing end points
python3 main.py

# start websocket end points - must be started if going to sync
python3 session_websockets.py
```

### API ENDPOINTS
__create new session for QR code__
```curl
[POST]
/sync/sessions/
```
```json
// body requirements
{
"auth_key":""
}

// returns
{
"status":200,
"url":""
}
```
