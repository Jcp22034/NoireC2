import sockets
import asyncio
import os
import json
import argparse


parser = argparse.ArgumentParser(description='A web-UI based C2 server written in Python designed for solo or team-based penetration testers.')
mainArgGroup = parser.add_mutually_exclusive_group()
mainArgGroup.add_argument('-nc', '--newConfig', action='store_true', help="Generate a new config file as 'config.json'")
mainArgGroup.add_argument('-c', '--config', default='config.json', help='The filepath of the config to use')
args = parser.parse_args()

if args.newConfig:
    with open('config.json','w') as f:
        f.write(json.dumps(
            {'webServerPort': 80,
            'c2ServerPort': 9595,
            'accounts': {
                'admin': {
                    'passwordHash': "",
                    'salt': "",
                    'groups': []
                }
            }}
        ))
    print("A default config file has been created at 'config.json'")
else:#block path to this directory and all subdirectories only? LFI?
    if not os.path.exists(args.config):#add check for valid config - needs corrct data? or just close if invalid
        print('The specified config file location cannot be accessed')
    else:
        global config
        with open(args.config,'r') as f:
            config = json.loads(f.read())
        #set all accounts salt to bytes
        print(config)