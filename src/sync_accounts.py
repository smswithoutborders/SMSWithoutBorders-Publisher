#!/bin/python

from . datastore import Datastore 
from . securitylayer import SecurityLayer
import uuid

def new_session(phonenumber, user_id):
   datastore = Datastore() 

   session_id = uuid.uuid4().hex
   create_status = datastore.new_session(phonenumber=phonenumber, _id=session_id, user_id=user_id)
   return session_id

def store_credentials(shared_key, public_key, session_id):
    datastore = Datastore()
    update_status = datastore.update_credentials(shared_key=shared_key, public_key=public_key, session_id=session_id)

def acquire_sessions(session_id):
    datastore = Datastore()
    results = datastore.acquireUserFromId(session_id=session_id)
    print(f"acquire_sessions_results: {results}")
    return results

def acquire_user_from_phonenumber(phonenumber):
    datastore = Datastore()
    results = datastore.acquireUserFromPhonenumber(SecurityLayer.sha512Hash(phonenumber))
    return results

def update_session(prev_session_id, session_id):
    datastore = Datastore()
    try:
        results = datastore.update_session_id(prev_session_id=prev_session_id, session_id=session_id)
    except Exception as error:
        raise Exception(error)
