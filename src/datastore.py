#!/bin/python import mysql.connector
import mysql.connector
import pymysql
from datetime import date
import os

# rewrite message store to allow for using as a class extension
class Datastore(object):
    def __init__(self, configs_filepath=None ):
        import configparser
        self.CONFIGS = configparser.ConfigParser(interpolation=None)

        if configs_filepath==None:
            PATH_CONFIG_FILE = os.path.join(os.path.dirname(__file__), '../configs', 'config.mysql.ini')
            self.CONFIGS.read(PATH_CONFIG_FILE)
        else:
            self.CONFIGS.read(configs_filepath)

        self.HOST = self.CONFIGS["MYSQL"]["HOST"]
        self.USER = self.CONFIGS["MYSQL"]["USER"]
        self.PASSWORD = self.CONFIGS["MYSQL"]["PASSWORD"]
        self.DATABASE = self.CONFIGS["MYSQL"]["DATABASE"]

        self.conn = pymysql.connect( host=self.HOST, user=self.USER, password=self.PASSWORD, database=self.DATABASE, cursorclass=pymysql.cursors.SSDictCursor)
        # self.cursor = self.conn.cursor(buffered=True)
        self.cursor = self.conn.cursor()

    def new_session(self, phonenumber, _id, user_id):
        query=f"INSERT INTO synced_accounts SET id=%s, phonenumber=%s, user_id=%s"
        try:
            self.cursor.execute( query, [_id, phonenumber, user_id])
            self.conn.commit()

        except mysql.connector.Error as err:
            raise Exception( err )
        else:
            return self.cursor.lastrowid

    def update_credentials(self, shared_key, public_key, session_id):
        query=f"UPDATE synced_accounts SET shared_key='{shared_key}', public_key='{public_key}' WHERE id='{session_id}'"
        try:
            self.cursor.execute( query )
            self.conn.commit()

        except mysql.connector.Error as err:
            raise Exception( err )
        else:
            self.cursor.lastrowid

    def acquireUserFromId(self, session_id):
        query = f"SELECT * from synced_accounts WHERE id='{session_id}'"
        try:
            self.cursor.execute( query )
            sms_message = self.cursor.fetchall()

            return sms_message

        except mysql.connector.Error as err:
            raise Exception( err )

    def acquireUserFromPhonenumber(self, phonenumber):
        query = f"SELECT * from synced_accounts WHERE id='{phonenumber}'"
        try:
            self.cursor.execute( query )
            sms_message = self.cursor.fetchall()

            return sms_message

        except mysql.connector.Error as err:
            raise Exception( err )

    def update_session_id(self, prev_session_id, session_id):
        query=f"UPDATE synced_accounts SET id='{session_id}' WHERE id='{prev_session_id}'"
        print(query)
        try:
            self.cursor.execute( query )
            self.conn.commit()

        except mysql.connector.Error as err:
            raise Exception( err )
        else:
            self.cursor.lastrowid

