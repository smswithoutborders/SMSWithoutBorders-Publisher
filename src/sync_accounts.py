#!/bin/python

from ldatastore import Datastore
import uuid

def new_session(phonenumber):
   datastore = Datastore() 

   session_id = _id=uuid.uuid4().hex
   create_status = datastore.new_session(phonenumber=phonenumber, _id=session_id)
   return session_id
