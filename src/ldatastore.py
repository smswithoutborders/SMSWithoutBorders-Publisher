#!/bin/python import mysql.connector
import mysql.connector
import pymysql
from datetime import date

# rewrite message store to allow for using as a class extension
class Datastore(object):
    def __init__(self, configs_filepath=None ):
        import configparser
        self.CONFIGS = configparser.ConfigParser(interpolation=None)

        if configs_filepath==None:
            self.CONFIGS.read("config.mysql.ini")
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
        query=f"INSERT INTO synced_accounts SET id='{_id}', phonenumber={phonenumber}, user_id={use_id}"
        try:
            self.cursor.execute( query )
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

    def release_message(self, messageID:int):
        query=f"UPDATE messages SET claimed_modem_imei=NULL WHERE id={messageID}"
        try:
            self.cursor.execute( query )
            self.conn.commit()

        except mysql.connector.Error as err:
            raise Exception( err )
        else:
            self.cursor.lastrowid

    def claim_message(self, messageID:int, modem_imei:str):
        query=f"UPDATE messages SET claimed_modem_imei={modem_imei} WHERE id={messageID}"
        try:
            self.cursor.execute( query )
            self.conn.commit()

        except mysql.connector.Error as err:
            raise Exception( err )
        else:
            self.cursor.lastrowid

    def acquireUserPhonenumber(self, session_id):
        query = f"SELECT user_id from synced_accounts WHERE id='{session_id}'"
        try:
            self.cursor.execute( query )
            sms_message = self.cursor.fetchall()

            return sms_message

        except mysql.connector.Error as err:
            raise Exception( err )


    def new_message(self, text:str, phonenumber:str, isp:str, _type:str, claimed_modem_imei=None):
        query = f"INSERT INTO messages SET text='{text}', phonenumber='{phonenumber}', isp='{isp}', type='{_type}'"
        if not claimed_modem_imei==None:
            query += f", claimed_modem_imei='{claimed_modem_imei}'"
        try:
            self.cursor.execute( query )
            self.conn.commit()
            messageID = self.cursor.lastrowid
            # messageID = self.conn.commit()
        except mysql.connector.Error as err:
            raise Exception( err )
        else:
            return messageID

    def get_all_received_messages(self):
        query = "SELECT * FROM messages WHERE type='received'"
        try:
            self.cursor.execute( query )
            messages = self.cursor.fetchall()
            return messages
        except mysql.connector.Error as err:
            raise Exception( err )

'''
    def fetch_for( data :dict):
        query = f"SELECT * FROM {tb_messages} WHERE "
        for key, value in data:

            appended=False
            # if one key needs to or many values
            if type(value)==type({}):
                query += "("
                _appended=False
                for _key, _value in value:
                    if _appended:
                        query += "OR "
                    if type(_value)==type(0): #int
                        query += f"{key}={value} "
                    else:
                        query += f"{key}='{value}' "
                    _appended=True
                query += ") "
            if appended:
                query+= "AND "
            if type(_value)==type(0): #int
                query += f"{key}={value} "
            else:
                query += f"{key}='{value}' "
            appended=True

        query += "WHERE state='pending' ORDER BY date DESC LIMIT 1"
'''
