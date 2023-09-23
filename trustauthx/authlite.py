import requests
from requests.exceptions import HTTPError
from jose import JWTError, jwt
from jose.constants import ALGORITHMS
import json

# authx/authlite.py

class AuthLiteClient:

    """
    AuthLiteClient is a Python client for the TrustAuthX authentication service.

    Attributes:
        api_key (str): The API key used for authentication.
        secret_key (str): The secret key used for JWT encoding.
        org_id (str): The organization ID for generating authentication URLs.
        signed_key (str): The signed key used for generating URLs.

    Methods:
        __init__(self, api_key, secret_key, org_id=None):
            Initializes the AuthLiteClient with the provided API key, secret key, and optional organization ID.

        generate_url(self) -> str:
            Generates an authentication URL for the given organization.

        generate_edit_user_url(self, access_token, url) -> str:
            Generates an authentication URL for editing user settings.

        re_auth(self, code):
            Performs re-authentication with a provided code.

        get_user(self, token) -> dict:
            Validates an authentication token and returns user data.

        get_user_data(self, AccessToken) -> dict:
            Retrieves user data using an access token.

        get_access_token_from_refresh_token(self, refresh_token):
            Retrieves an access token from a refresh token.

        validate_access_token(self, access_token) -> bool:
            Validates an access token.

        revoke_token(self, AccessToken=None, RefreshToken=None, revoke_all_tokens=False) -> bool:
            Revokes an access token or refresh token.

        validate_token_set(self, access_token, refresh_token) -> TokenCheck:
            Validates a set of access and refresh tokens.

    """
    
    class TokenCheck:
        """
        TokenCheck is a nested class for representing the state of access and refresh tokens.

        Attributes:
            access (str): The access token.
            refresh (str): The refresh token.
            state (bool): The state of the tokens (True if valid, False otherwise).
        """
        access :str
        refresh:str
        state:bool
    
    def __init__(self, api_key, secret_key, org_id=None):
        """
        Initializes an AuthLiteClient instance.

        Args:
            api_key (str): The API key used for authentication.
            secret_key (str): The secret key used for JWT encoding.
            org_id (str, optional): The organization ID for generating authentication URLs.

        Returns:
            None
        """
        self.jwt_encode = lambda key, data: jwt.encode(data, key=key, algorithm= ALGORITHMS.HS256)
        self.jwt_decode = lambda key, data: jwt.decode(str(data), key=key, algorithms=ALGORITHMS.HS256)
        self.secret_key = secret_key
        self.api_key = api_key
        self.org_id = org_id
        self.signed_key = self.jwt_encode(key=self.secret_key, data={"api_key":self.api_key})

    def generate_url(self) -> str:
        """
        Generates an authentication URL for the given organization.

        Returns:
            str: The generated authentication URL.
        
        Raises:
            ValueError: If org_id is not provided.
        """
        # Generate an authentication url for the given org
        if self.org_id:return f"https://app.trustauthx.com/widget/login/?org_id={self.org_id}"
        else:raise ValueError("must provide org_id")

    def generate_edit_user_url(self, access_token, url) -> str:
        """
        Generates an authentication URL for editing user settings.

        Args:
            access_token (str): The access token for authentication.
            url (str): The URL to be included in the generated URL.

        Returns:
            str: The generated authentication URL.
        """
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
        """
        Performs re-authentication with a provided code after the user finishes Editing profile.

        Args:
            code (str): The re-authentication code.

        Returns:
            dict: A dictionary containing user information after successful re-authentication.

        Raises:
            HTTPError: If the request fails with an HTTP error status code.
        """
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
        """
        Validates the given authentication token and returns user data.

        Args:
            token (str): The authentication token to validate.

        Returns:
            dict: A dictionary containing user information.
            returns a dict containing 'access_token', 'refresh_token', 'img', 'sub'
        Raises:
            HTTPError: If the request fails with an HTTP error status code.
        """
        # Validate the given authentication token
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
    
    def get_user_data(self, AccessToken) -> dict:
        """
        Retrieves user data using an access token.

        Args:
            AccessToken (str): The access token for retrieving user data.

        Returns:
            dict: A dictionary containing user data.

        Raises:
            HTTPError: If the request fails with an HTTP error status code.
        """
        # Validate the given authentication token
        """returns a dict containing 'access_token', 'refresh_token', 'img', 'sub'"""
        url = 'https://api.trustauthx.com/api/user/me/data'
        headers = {'accept': 'application/json'}
        params = {
            'AccessToken': AccessToken,
            'api_key': self.api_key,
            'signed_key': self.signed_key
                 }
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            rtn = self.jwt_decode(self.secret_key,response.json())
            return rtn
        else:raise HTTPError(
            'Request failed with status code : {} \n this code contains a msg : {}'.format(
                                                                            response.status_code, 
                                                                            response.text)
                            )

    def get_access_token_from_refresh_token(self, refresh_token):
        """
        Retrieves an access token from a refresh token.

        Args:
            refresh_token (str): The refresh token for obtaining a new access token.

        Returns:
            dict: A dictionary containing the new access and refresh tokens.

        Raises:
            HTTPError: If the request fails with an HTTP error status code.
        """
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
        """
        Validates an access token.

        Args:
            access_token (str): The access token to validate.

        Returns:
            bool: True if the access token is valid, False otherwise.
        """
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
        """
        Revokes an access token or refresh token.

        Args:
            AccessToken (str, optional): The access token to revoke.
            RefreshToken (str, optional): The refresh token to revoke.
            revoke_all_tokens (bool): Whether to revoke all tokens associated with the user.

        Returns:
            bool: True if the token(s) were successfully revoked, False otherwise.

        Raises:
            HTTPError: If the request fails with an HTTP error status code.
            AttributeError: If neither AccessToken nor RefreshToken is provided.
        """
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
        """
        Validates a set of access and refresh tokens.

        Args:
            access_token (str): The access token to validate.
            refresh_token (str): The refresh token to validate.

        Returns:
            TokenCheck: An instance of TokenCheck representing the state of the tokens.

        Raises:
            HTTPError: If both tokens are invalid, indicating the need to login again.
        """
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