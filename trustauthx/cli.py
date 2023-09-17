import argparse
from .llmai import LLMAI_Inter
import subprocess
import sys, os

def check() -> bool:
    parser = argparse.ArgumentParser(prog='trustauthx')
    parser.add_argument('-k', required=True)
    parser.add_argument('-s', required=True)
    args = parser.parse_args()
    os.environ['API_KEY'] = args.k
    os.environ['API_SECRET'] = args.s
    api_key = os.environ.get('API_KEY')
    api_secret = os.environ.get('API_SECRET')
    a = LLMAI_Inter.arb_login(api_key, api_secret)
    return a

def main():

    api_key = os.environ.get('API_KEY')
    api_secret = os.environ.get('API_SECRET')
    if not check(): return "invalid credential"

    parser = argparse.ArgumentParser(prog='trustauthx')

    parser.add_argument('command')
    parser.add_argument('framework', required=True)
    parser.add_argument('-out', default=None)

    args = parser.parse_args()

    if args.command == 'neurocraft':
        sdk = LLMAI_Inter(
                    api_key=api_key, 
                    secret_key=api_secret, 
                    framework=args.framework
                        )
        print("getting req. dependencies:")
        list_depends = sdk.Install_dependancies()
        print(list_depends)
        print("Installing dependencies...")
        def install(packages):
            for package in packages:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        install(list_depends)
        print("Dependencies installed.")
        a = sdk.Create_App(out=args.out)
        print(a)
        b = sdk.Start_server()
        process = subprocess.Popen(b, shell=True)
        process.wait()

    if args.command == 'fabricate':
        sdk = LLMAI_Inter(
                    api_key=api_key, 
                    secret_key=api_secret, 
                    framework=args.framework
                        )
        print("getting req. dependencies:")
        list_depends = sdk.Install_dependancies()
        print(list_depends)
        print("Installing dependencies...")
        def install(packages):
            for package in packages:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        install(list_depends)
        print("Dependencies installed.")
        a = sdk.Create_App(out=args.out)
        print(a)

if __name__ == '__main__':
    main()
