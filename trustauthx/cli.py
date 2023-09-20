import argparse
from .llmai import LLMAI_Inter
import subprocess
import sys, os

def check() -> bool:
    global client
    api_key = os.environ.get('API_KEY')
    api_secret = os.environ.get('API_SECRET')
    org_id = os.environ.get('ORG_ID')
    parser = argparse.ArgumentParser(prog='trustauthx')
    parser.add_argument('-k', required=not api_key)
    parser.add_argument('-s', required=not api_secret)
    parser.add_argument('-o', required=not org_id)
    args = parser.parse_args()
    if args.k: os.environ['API_KEY'] = args.k
    if args.s: os.environ['API_SECRET'] = args.s
    if args.o: os.environ['ORG_ID'] = args.o
    api_key = os.environ.get('API_KEY')
    api_secret = os.environ.get('API_SECRET')
    org_id = os.environ.get('ORG_ID')
    client = LLMAI_Inter(api_key, api_secret, org_id)
    return client.arb_login()

def main():

    if not check(): return "invalid credential"

    api_key = os.environ.get('API_KEY')
    api_secret = os.environ.get('API_SECRET')
    org_id = os.environ.get('ORG_ID')

    parser = argparse.ArgumentParser(prog='trustauthx')

    parser.add_argument('command')
    parser.add_argument('framework', required=True)
    parser.add_argument('-out', default=None)

    args = parser.parse_args()

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
        a = sdk.Create_App(out=args.out, path=os.getcwd())
        print(a)
        print("App named --> authx.py")
        print(f"app located at --> {os.path.join(os.getcwd(), 'authx.py')}")
        print("App creation Successful...")
        print(f"you could start the server with command trustauthx start {args.framework}")
    
    if args.command == 'start':
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