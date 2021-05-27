### Dependencies
- MySQL

### Configuration and running
__mysql__
```bash
# copy router.example.config.ini to config.router.ini
cp router.example.config.ini config.router.ini
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
python main.py
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
