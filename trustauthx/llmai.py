import requests
from requests.exceptions import HTTPError
import json
from .authlite import AuthLiteClient

class LLMAI_Inter:
    
    def __init__(self, api_key:str, secret_key:str, framework:str):
        self.api_key = api_key
        self.signed_key = AuthLiteClient.jwt_encode(key=secret_key, data={"api_key":self.api_key})
        self.framework = framework
    
    def arb_login(self) -> bool:
        # Store the given authentication token
        url = 'https://api.trustauthx.com/api/app-build-ai/login'
        headers = {'accept': 'application/json'}
        params = {
            'api_key': self.api_key,
            'signed_key': self.signed_key
                 }
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:return True
        else:raise HTTPError(
            'Request failed with status code : {} \n this code contains a msg : {}'.format(
                                                                            response.status_code, 
                                                                            response.text)
                            )

    def Create_App(self, out:str=None):
        # Store the given authentication token
        url = 'https://api.trustauthx.com/api/app-build-ai/create'
        headers = {'accept': 'application/json'}
        params = {
            'framework': self.framework,
            'api_key': self.api_key,
            'signed_key': self.signed_key
                 }
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            if out:out=out
            else:out=f"trustauthx_{self.framework}"
            with open(f'{out}.py', 'wb') as f:
                f.write(response.content)
            return f"{out} app construction successful"
        else:raise HTTPError(
            'Request failed with status code : {} \n this code contains a msg : {}'.format(
                                                                            response.status_code, 
                                                                            response.text)
                            )
    
    def Install_dependancies(self) -> list:
        url = 'https://api.trustauthx.com/api/app-build-ai/install'
        headers = {'accept': 'application/json'}
        params = {
            'framework': self.framework,
            'api_key': self.api_key,
            'signed_key': self.signed_key
                 }
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:return list(response.json())
        else:raise HTTPError(
            'Request failed with status code : {} \n this code contains a msg : {}'.format(
                                                                            response.status_code, 
                                                                            response.text)
                            )
    
    def Start_server(self):
        url = 'https://api.trustauthx.com/api/app-build-ai/start'
        headers = {'accept': 'application/json'}
        params = {
            'framework': self.framework,
            'api_key': self.api_key,
            'signed_key': self.signed_key
                 }
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:return response.json()
        else:raise HTTPError(
            'Request failed with status code : {} \n this code contains a msg : {}'.format(
                                                                            response.status_code, 
                                                                            response.text)
                            )