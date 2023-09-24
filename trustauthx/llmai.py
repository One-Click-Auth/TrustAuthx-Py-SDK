import requests
from requests.exceptions import HTTPError
import json, os
from jose import JWTError, jwt
from jose.constants import ALGORITHMS

class LLMAI_Inter:
    
    def __init__(self, api_key:str, secret_key:str, org_id:str,framework:str ):
        self.jwt_encode = lambda key, data: jwt.encode(data, key=key, algorithm= ALGORITHMS.HS256)
        self.jwt_decode = lambda key, data: jwt.decode(str(data), key=key, algorithms=ALGORITHMS.HS256)
        self.api_key = api_key
        print("--------------------------->")
        print(type(secret_key))
        print(secret_key)
        print("<---------------------------")
        self.signed_key = self.jwt_encode(key=secret_key, data={"api_key":self.api_key})
        self.framework = framework
        self.org_id = org_id
    
    def arb_login(self) -> bool:
        # Store the given authentication token
        url = 'https://api.trustauthx.com/api/app-build-ai/login'
        headers = {'accept': 'application/json'}
        params = {
            'org_id': self.org_id,
            'api_key': self.api_key,
            'signed_key': self.signed_key
                 }
        response = requests.post(url, headers=headers, params=params)
        if response.status_code == 200:return True
        else:raise HTTPError(
            'Request failed with status code : {} \n this code contains a msg : {}'.format(
                                                                            response.status_code, 
                                                                            response.text)
                            )

    def Create_App(self, path):
        url = 'https://api.trustauthx.com/api/app-build-ai/create'
        headers = {'accept': 'application/octet-stream'}
        params = {
            'framework': self.framework,
            'api_key': self.api_key,
            'signed_key': self.signed_key,
            'org_id':self.org_id
        }
        response = requests.post(url, headers=headers, params=params, stream=True)
        if response.status_code == 200:
            with open(os.path.join(path, 'authx.py'), 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            return "authx.py app construction successful"
        else:
            raise HTTPError(
                f'Request failed with status code : {response.status_code} \n this code contains a msg : {response.text}'
            )

    def Install_dependancies(self) -> list:
        url = 'https://api.trustauthx.com/api/app-build-ai/install'
        headers = {'accept': 'application/json'}
        params = {
            'framework': self.framework,
            'api_key': self.api_key,
            'signed_key': self.signed_key,
            'org_id':self.org_id
                 }
        response = requests.post(url, headers=headers, params=params)
        if response.status_code == 200:
            resp = response.json()
            return resp["cmd"]
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
            'signed_key': self.signed_key,
            'org_id':self.org_id
                 }
        response = requests.post(url, headers=headers, params=params)
        if response.status_code == 200:
            resp =response.json()
            return resp["cmd"]
        else:raise HTTPError(
            'Request failed with status code : {} \n this code contains a msg : {}'.format(
                                                                            response.status_code, 
                                                                            response.text)
                            )