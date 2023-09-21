import argparse
from .llmai import LLMAI_Inter
import subprocess
import sys, os
from dotenv import load_dotenv

def main():
    parser = argparse.ArgumentParser(prog='trustauthx')
    load_dotenv()
    api_key = os.environ.get('API_KEY')
    api_secret = os.environ.get('API_SECRET')
    org_id = os.environ.get('ORG_ID')
    
    parser.add_argument('command')
    parser.add_argument('framework')

    parser.add_argument('-k', required=not api_key, help='API key')
    parser.add_argument('-s', required=not api_secret, help='API secret')
    parser.add_argument('-o', required=not org_id, help='Organization ID')

    args = parser.parse_args()
    try:
        if args.k and args.s and args.o:
            env_vars = {
                "API_KEY": args.k,
                "API_SECRET": args.s,
                "ORG_ID": args.o
            }
            with open('.env', 'w') as f:
                for key, value in env_vars.items():
                    f.write(f'{key}={value}\n')
    except:pass
    client = LLMAI_Inter(api_key, api_secret, org_id, "")
    if not client.arb_login():raise ConnectionRefusedError("user not found, invalid credential")

    if args.command == 'neuroform':
        client.framework=args.framework
        sdk = client
        print("getting req. dependencies:")
        list_depends = sdk.Install_dependancies()
        print(list_depends)
        print("Installing dependencies...")
        def install(packages):
            for package in packages:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        install(list_depends)
        print("Dependencies installed.")
        a = sdk.Create_App(path=os.getcwd())
        print(a)
        print("App named --> authx.py")
        print(f"app located at --> {os.path.join(os.getcwd(), 'authx.py')}")
        print("App creation Successful...")
        print(f"you could start the server with command trustauthx start {args.framework}")
    
    if args.command == 'start':
        client.framework=args.framework
        sdk = client
        print("Trying to start local server ...")
        print("this command might fail in case of few frameworks in such cases consider installing req. lib. and starting server manually")
        b = sdk.Start_server()
        process = subprocess.Popen(b, shell=True)
        process.wait()

if __name__ == '__main__':
    main()


    # if args.command == 'fabricate':
    #     client.framework=args.framework
    #     sdk = client
    #     print("getting req. dependencies:")
    #     list_depends = sdk.Install_dependancies()
    #     print(list_depends)
    #     print("Installing dependencies...")
    #     def install(packages):
    #         for package in packages:
    #             subprocess.check_call([sys.executable, "-m", "pip", "install", package])
    #     install(list_depends)
    #     print("Dependencies installed.")
    #     a = sdk.Create_App(out=args.out)
    #     print(a)