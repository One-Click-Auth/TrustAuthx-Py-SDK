import requests
from requests.exceptions import HTTPError
from jose import JWTError, jwt
from jose.constants import ALGORITHMS

# authx/authlite.py

class AuthLiteClient:

    def __init__(self, api_key, secret_key, org_id=None):
        self.jwt_encode = lambda key, data: jwt.encode(data, key=key, algorithm= ALGORITHMS.HS256)
        self.jwt_decode = lambda key, data: jwt.decode(data, key=key, algorithms=ALGORITHMS.HS256)
        self.secret_key = secret_key
        self.api_key = api_key
        self.org_id = org_id
        self.signed_key = self.jwt_encode(key=self.secret_key, data={"api_key":self.api_key})

    def generate_url(self) -> str:
        # Generate an authentication url for the given org
        if self.org_id:return f"https://app.trustauthx.com/widget/login/{self.org_id}"
        else:return ""

    def get_user(self, token) -> dict:
        # Validate the given authentication token
        url = 'https://api.trustauthx.com/api/user/me/auth/data'
        headers = {'accept': 'application/json'}
        params = {
            'UserToken': token,
            'api_key': self.api_key,
            'signed_key': self.signed_key
                 }
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:return self.jwt_decode(self.secret_key,response.json())
        else:raise HTTPError(
            'Request failed with status code : {} \n this code contains a msg : {}'.format(
                                                                            response.status_code, 
                                                                            response.text)
                            )

    def get_access_token_from_refresh_token(self, refresh_token):
        # Store the given authentication token
        url = 'https://api.trustauthx.com/api/user/me/access/token/'
        headers = {'accept': 'application/json'}
        params = {
            'RefreshToken': refresh_token,
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

    def validate_access_token(self, access_token) -> bool:
        # Store the given authentication token
        url = 'https://api.trustauthx.com/api/user/me/auth/validate/token'
        headers = {'accept': 'application/json'}
        params = {
            'AccessToken': access_token,
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
    
    def revoke_token(self, RefreshToken:bool = True, AccessToken:bool = False, revoke_all_tokens:bool = False) -> bool:
        url = 'https://api.trustauthx.com/api/user/me/token/'
        headers = {'accept': 'application/json'}
        tt=True if AccessToken else False
        t = AccessToken if AccessToken else RefreshToken
        params = {
            'Token': t,
            'api_key': self.api_key,
            'signed_key': self.secret_key,
            'AccessToken': tt,
            'SpecificTokenOnly':not revoke_all_tokens,
                }
        response = requests.delete(url, headers=headers, params=params)
        if response.status_code == 200:return response.json()
        else:raise HTTPError(
            'Request failed with status code : {} \n this code contains a msg : {}'.format(response.status_code, response.text))