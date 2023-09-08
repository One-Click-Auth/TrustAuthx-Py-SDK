import requests
from requests.exceptions import HTTPError
from jose import JWTError, jwt
from jose.constants import ALGORITHMS
import json

# authx/authlite.py

class AuthLiteClient:

    class TokenCheck:
        access :str
        refresh:str
        state:bool
    
    def __init__(self, api_key, secret_key, org_id=None):
        self.jwt_encode = lambda key, data: jwt.encode(data, key=key, algorithm= ALGORITHMS.HS256)
        self.jwt_decode = lambda key, data: jwt.decode(str(data), key=key, algorithms=ALGORITHMS.HS256)
        self.secret_key = secret_key
        self.api_key = api_key
        self.org_id = org_id
        self.signed_key = self.jwt_encode(key=self.secret_key, data={"api_key":self.api_key})

    def generate_url(self) -> str:
        # Generate an authentication url for the given org
        if self.org_id:return f"https://app.trustauthx.com/widget/login/?org_id={self.org_id}"
        else:raise ValueError("must provide org_id")

    def generate_edit_user_url(self, access_token, url) -> str:
        # Generate an authentication url for the given org
        headers = {'accept': 'application/json'}
        params = {
            'AccessToken': access_token,
            'api_key': self.api_key,
            'signed_key': self.signed_key,
            'url':url
                 }
        url = "https://api.trustauthx.com/api/user/me/settings/"
        req = requests.Request('GET', url, params=params, headers=headers).prepare()
        return req.url

    def re_auth(self, code):
        url = "https://api.trustauthx.com/api/user/me/widget/re-auth/token"
        params = {
            "code": code,
            'api_key': self.api_key,
            'signed_key': self.signed_key
        }
        headers = {"accept": "application/json"}
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            rtn = self.jwt_decode(self.secret_key,response.json())
            sub = json.loads(rtn["sub"])
            rtn.pop("sub")
            rtn["email"] = sub["email"]
            rtn["uid"] = sub["uid"]
            return rtn
        else:raise HTTPError(
            'Request failed with status code : {} \n this code contains a msg : {}'.format(
                                                                            response.status_code, 
                                                                            response.text)
                            )

    def get_user(self, token) -> dict:
        # Validate the given authentication token
        """returns a dict containing 'access_token', 'refresh_token', 'img', 'sub'"""
        url = 'https://api.trustauthx.com/api/user/me/auth/data'
        headers = {'accept': 'application/json'}
        params = {
            'UserToken': token,
            'api_key': self.api_key,
            'signed_key': self.signed_key
                 }
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            rtn = self.jwt_decode(self.secret_key,response.json())
            sub = json.loads(rtn["sub"])
            rtn.pop("sub")
            rtn["email"] = sub["email"]
            rtn["uid"] = sub["uid"]
            return rtn
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
        return response.status_code == 200
    
    def revoke_token(self,AccessToken:str=None, RefreshToken:str = None, revoke_all_tokens:bool = False) -> bool:
        url = 'https://api.trustauthx.com/api/user/me/token/'
        headers = {'accept': 'application/json'}
        if not AccessToken and not RefreshToken:raise AttributeError("must provide either AccessToken or RefreshToken")
        tt=True if AccessToken else False
        t = AccessToken if AccessToken else RefreshToken
        params = {
            'Token': t,
            'api_key': self.api_key,
            'signed_key': self.signed_key,
            'AccessToken': tt,
            'SpecificTokenOnly':not revoke_all_tokens,
                }
        response = requests.delete(url, headers=headers, params=params)
        if response.status_code == 200:return response.json()
        else:raise HTTPError(
            'Request failed with status code : {} \n this code contains a msg : {}'.format(response.status_code, response.text))
    
    def validate_token_set(self, access_token, refresh_token) -> TokenCheck:
        try:
            d = self.TokenCheck()
            is_valid = self.validate_access_token(access_token)
            if not is_valid:
                if refresh_token:
                    new_tokens = self.get_access_token_from_refresh_token(refresh_token)
                    d.state = False
                    d.access = new_tokens['access_token']
                    d.refresh = new_tokens['refresh_token']
                return d
            else:
                d.state = True
                d.access = access_token
                d.refresh = refresh_token
                return d
        except:
            raise HTTPError('both tokens are invalid login again')