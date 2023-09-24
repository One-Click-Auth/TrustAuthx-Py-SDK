import argparse
from .llmai import LLMAI_Inter
import subprocess
import sys, os, time
from dotenv import load_dotenv

def main():
    parser = argparse.ArgumentParser(prog='trustauthx')
    load_dotenv(dotenv_path='./.env', override=True, verbose=True)
    api_key = os.environ.get('API_KEY')
    api_secret = os.environ.get('API_SECRET')
    org_id = os.environ.get('ORG_ID')
    
    parser.add_argument('command')
    parser.add_argument('framework')

    parser.add_argument('-k', required=not api_key, help='API key')
    parser.add_argument('-s', required=not api_secret, help='API secret')
    parser.add_argument('-o', required=not org_id, help='Organization ID')

    args = parser.parse_args()
    # try:
    if args.k and args.s and args.o:
        if api_key or api_secret or org_id:
            file_path = './.env'
            if os.path.isfile(file_path):
                os.remove(file_path)
            else:
                print(f"Error: {file_path} not a valid filename")
            time.sleep(0.5)
            print("\nattempt to Logout TrustAuthx Build AI successful")
            time.sleep(1)
            print("\nEverything Done Status 200, Successfully logged out")
        else:
            env_vars = {
                "API_KEY": args.k,
                "API_SECRET": args.s,
                "ORG_ID": args.o
                }
            with open('.env', 'w') as f:
                for key, value in env_vars.items():
                    f.write(f'{key}={value}\n')
            load_dotenv(dotenv_path='./.env', override=True, verbose=True)
            api_key = os.environ.get('API_KEY')
            api_secret = os.environ.get('API_SECRET')
            org_id = os.environ.get('ORG_ID')

    if api_key or api_secret or org_id: pass
    else: print(f"no .env found, api_key {not bool(api_key)}, api_secret {not bool(api_secret)}, org_id {not bool(org_id)}")

    client = LLMAI_Inter(api_key, api_secret, org_id, "")
    print("\ngetting auth status ...") 
    if not client.arb_login():raise ConnectionRefusedError("user not found, invalid credential")
    print("\nauthorization success, credentials valid")
    
    if args.command == 'neuroform':
        client.framework=args.framework
        sdk = client
        print("\ngetting req. dependencies:")
        list_depends = sdk.Install_dependancies()
        print(list_depends)
        print("\nInstalling dependencies...")
        def install(packages):
            for package in packages:
                if str(package).__len__() > 1 :subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                else:pass
        install(list_depends)
        print("\nDependencies installed.")
        a = sdk.Create_App(path=os.getcwd())
        print(a)
        print("\nApp named --> authx.py")
        print(f"\napp located at --> {os.path.join(os.getcwd(), 'authx.py')}")
        print("\nApp creation Successful...")
        print(f"\nyou could start the server with command trustauthx start {args.framework}")
    
    if args.command == 'start':
        client.framework=args.framework
        sdk = client
        print("\nTrying to start local server ...")
        print("\nthis command might fail in case of few frameworks in such cases consider installing req. lib. and starting server manually")
        b = sdk.Start_server()
        process = subprocess.Popen(b, shell=True)
        process.wait()

    if args.command == 'login':
        time.sleep(0.5)
        print("\nattempt to Login TrustAuthx Build AI successful")
        print("\nExecuting Rate-Limit")
        time.sleep(1)
        print("\nEverything Done Status 200, Ready To Start")

    if args.command == 'logout':
        file_path = './.env'
        if os.path.isfile(file_path):
            os.remove(file_path)
        else:
            print(f"Error: {file_path} not a valid filename")
        time.sleep(0.5)
        print("\nattempt to Logout TrustAuthx Build AI successful")
        time.sleep(1)
        print("\nEverything Done Status 200, Successfully logged out")

if __name__ == '__main__':
    main()


    # if args.command == 'fabricate':
    #     client.framework=args.framework
    #     sdk = client
    #     print("\ngetting req. dependencies:")
    #     list_depends = sdk.Install_dependancies()
    #     print(list_depends)
    #     print("\nInstalling dependencies...")
    #     def install(packages):
    #         for package in packages:
    #             subprocess.check_call([sys.executable, "-m", "pip", "install", package])
    #     install(list_depends)
    #     print("\nDependencies installed.")
    #     a = sdk.Create_App(out=args.out)
    #     print(a)