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
        f.write('''{
    "httpServerPort": 5000,
    "C2ServerPort": 9595,
    "httpC2Server": true
}''')
    print("A default config file has been created at 'config.json'")
else:#block path to this directory and all subdirectories only? LFI?
    if not os.path.exists(args.config):#add check for valid config - needs corrct data? or just close if invalid
        print('The specified config file location cannot be accessed')
    else:
        global config
        with open(args.config,'r') as f:
            config = json.loads(f.read())
        import concurrent.futures
        from modules import webServer, C2Server
        if config['httpC2Server']:
            webServer.start_server(config['httpServerPort'])
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                web_server_future = executor.submit(webServer.start_server, port=config['httpServerPort'])
                print(web_server_future.exception)
                tcp_server_future = executor.submit(C2Server.start_server, port=config['C2ServerPort'])
                concurrent.futures.wait([web_server_future, tcp_server_future])
        print("Finished")