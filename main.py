#! /usr/bin/env python3                                                                                                                                                                                                                       

# references: 
#  - https://rtfm.co.ua/en/chromium-linux-keyrings-secret-service-passwords-encryption-and-store/#Python_script_to_obtain_Chromiums_passwords
#  - https://github.com/jaraco/keyring/issues/151#issuecomment-1111685038

import sqlite3

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

import secretstorage

def get_keyrings_secret():
    bus = secretstorage.dbus_init()
    collection = secretstorage.get_default_collection(bus)
    for item in collection.get_all_items():
        if item.get_label() == "Chrome Safe Storage":
            # print(item.get_secret().decode("utf-8"))
            keyring_secret = item.get_secret().decode("utf-8")
    
    return keyring_secret


def get_encrypted_data(db_path):

    # choose a database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # connect and egt exncypted data
    data = cursor.execute('SELECT action_url, username_value, password_value FROM logins')
    
    return data


# to get rid of padding
def clean(x): 
    return x[:-x[-1]].decode('utf8')


def get_decrypted_data(encrypted_password):

    # print("Decrypting the string: {}".format(encrypted_password))

    # trim off the 'v10' that Chrome/ium prepends
    encrypted_password = encrypted_password[3:]
    keyring_secret = get_keyrings_secret()

    # making the key
    salt = b'saltysalt'
    iv = b' ' * 16
    length = 16
    iterations = 1
    pb_pass = keyring_secret.encode('utf8')
    # pb_pass = "peanuts".encode('utf8')


    key = PBKDF2(pb_pass, salt, length, iterations)
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    
    decrypted = cipher.decrypt(encrypted_password)
    # print(clean(decrypted))
    return clean(decrypted)


if __name__ == "__main__":
    db_path = '/home/ctwo/.config/google-chrome/Default/Login Data'
    for url, user, encrypted_password in get_encrypted_data(db_path):
        if encrypted_password:
            print()
            password = get_decrypted_data(encrypted_password)

            print(f'URL: {url}')
            print(f'USERNAME: {user}')
            print(f'PASS: {password}')
