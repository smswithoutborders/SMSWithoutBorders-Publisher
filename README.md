##### Begin by configuring databases
###### MySQL
- Copy the _router.example.config.ini_ file into _config.router.ini_ in the same dir

##### How to Run

###### Create venv
```bash
python3 -m virtualenv .venv
```

###### Activate venv
```bash
source .venv/bin/activate
```

###### Install requirements
```bash
pip install -r requirements.txt
```

###### Start the API
```bash
cd src/
python router.py
```
