import requests
from requests.exceptions import HTTPError
from jose import JWTError, jwt
from jose.constants import ALGORITHMS
import json
import sqlite3
from dataclasses import dataclass, asdict
from typing import List, Dict

@dataclass
class Permission:
    name: str
    value: str

@dataclass
class Role:
    org_id: str
    rol_id: str
    name: str
    permissions: List[Permission]

class _EdgeDBRoleQuery:
    def __init__(self, roles, in_memory=True):
        self.in_memory = in_memory
        if self.in_memory:
            self.roles = {role_id: permissions for role in roles for role_id, permissions in role.items()}
        else:
            self.conn = sqlite3.connect(':memory:')  # replace ':memory:' with your database path
            self.cursor = self.conn.cursor()
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS roles (
                    role_id TEXT PRIMARY KEY,
                    permissions TEXT
                )
            """)
            for role in roles:
                for role_id, permissions in role.items():
                    self.cursor.execute("INSERT INTO roles VALUES (?, ?)", (role_id, permissions))
            self.conn.commit()

    def query(self, role_id=None, permission_key=None):
        if self.in_memory:
            if role_id and permission_key:
                return self.roles.get(role_id, {}).get(permission_key, None)
            elif role_id:
                return self.roles.get(role_id, None)
            elif permission_key:
                return {role_id: permissions[permission_key] for role_id, permissions in self.roles.items() if permission_key in permissions}
            else:
                return self.roles
        else:
            if role_id and permission_key:
                self.cursor.execute("SELECT permissions FROM roles WHERE role_id = ?", (role_id,))
                permissions = self.cursor.fetchone()
                if permissions:
                    return permissions[0].get(permission_key, None)
            elif role_id:
                self.cursor.execute("SELECT permissions FROM roles WHERE role_id = ?", (role_id,))
                return self.cursor.fetchone()
            elif permission_key:
                self.cursor.execute("SELECT * FROM roles")
                return {role_id: permissions[permission_key] for role_id, permissions in self.cursor.fetchall() if permission_key in permissions}
            else:
                self.cursor.execute("SELECT * FROM roles")
                return self.cursor.fetchall()

    def validate(self, role_id, permission_key, permission_val):
        if self.in_memory:
            return self.roles.get(role_id, {}).get(permission_key, None) == permission_val
        else:
            self.cursor.execute("SELECT permissions FROM roles WHERE role_id = ?", (role_id,))
            permissions = self.cursor.fetchone()
            if permissions:
                return permissions[0].get(permission_key, None) == permission_val

    def count_roles(self):
        if self.in_memory:
            return len(self.roles)
        else:
            self.cursor.execute("SELECT COUNT(*) FROM roles")
            return self.cursor.fetchone()[0]

class _Roles(_EdgeDBRoleQuery):
    def __init__(self, roles, org_id, api_key, signed_key, secret_key, API_BASE_URL, InMemory=True):
        self.org_id = org_id
        self.api_key = api_key
        self._secret_key = secret_key
        self.signed_key = signed_key
        self.API_BASE_URL = API_BASE_URL
        super().__init__(roles, in_memory=InMemory)
        print(self.roles)

    def get_all_roles(self):
        """[
  {
    "org_id": "4195502c85984d27ae1aceb677d99551543808625aeb11ee88069dc8f7663e88",
    "rol_id": "rol_gCD_ebc6f7715bb14554",
    "name": "string",
    "permissions": [
      {
        "user": "administration"
      }
    ]
  },
  {
    "org_id": "4195502c85984d27ae1aceb677d99551543808625aeb11ee88069dc8f7663e88",
    "rol_id": "rol_Ahy_f51d73ff656545e5",
    "name": "string",
    "permissions": []
  },
  {
    "org_id": "4195502c85984d27ae1aceb677d99551543808625aeb11ee88069dc8f7663e88",
    "rol_id": "rol_rce_474ae9e59b3d49ce",
    "name": "string",
    "permissions": [
      {
        "user": "administration"
      },
      {
        "viewer": "administration"
      },
      {
        "maintainer": "administration"
      }
    ]
  }
]"""
        url = f'{self.API_BASE_URL}/rbac/role'
        headers = {'accept': 'application/json'}
        params = {
            'org_id': f'{self.org_id}',
            'api_key': f'{self.api_key}',
            'signed_key': f'{self._secret_key}'
        }
        response = requests.get(url, headers=headers, params=params)
        roles = [Role(**role_data) for role_data in response.json()]
        return roles

    def add_role(self, name, **Permission):
        """{
  "org_id": "4195502c85984d27ae1aceb677d99551543808625aeb11ee88069dc8f7663e88",
  "rol_id": "rol_rce_474ae9e59b3d49ce",
  "name": "string",
  "permissions": [
    {
      "user": "administration"
    },
    {
      "viewer": "administration"
    },
    {
      "maintainer": "administration"
    }
  ]
}"""
        url = f'{self.API_BASE_URL}/rbac/role'
        headers = {
            'accept': 'application/json',
            'Content-Type': 'application/json'
        }
        params = {
            'org_id': f'{self.org_id}',
            'api_key': f'{self.api_key}',
            'signed_key': f'{self._secret_key}'
        }
        permissions = [{k: v} for k, v in Permission.items()]
        data = {
            "org_id": f'{self.org_id}',
            "name": name,
            "permissions": permissions
        }
        response = requests.post(url, headers=headers, params=params, data=json.dumps(data))
        return response.json()

    def delete_role(self, rol_id):

        """{
  "org_id": "4195502c85984d27ae1aceb677d99551543808625aeb11ee88069dc8f7663e88",
  "rol_id": "rol_YHV_78ae9006bcaa4c77",
  "name": "string",
  "permissions": [
    {
      "user": "administration"
    },
    {
      "viewer": "administration"
    },
    {
      "maintainer": "administration"
    }
  ]
}"""
        url = f'{self.API_BASE_URL}/rbac/role'
        headers = {
            'accept': 'application/json',
            'Content-Type': 'application/json'
        }
        params = {
            'org_id': f'{self.org_id}',
            'api_key': f'{self.api_key}',
            'signed_key': f'{self._secret_key}'
        }
        data = {
            "org_id": f'{self.org_id}',
            "rol_id": rol_id
        }
        response = requests.delete(url, headers=headers, params=params, data=json.dumps(data))
        return response.json()

    def add_permission(self, rol_id, **Permission):
        """{
  "org_id": "4195502c85984d27ae1aceb677d99551543808625aeb11ee88069dc8f7663e88",
  "rol_id": "rol_rce_474ae9e59b3d49ce",
  "permissions": [
    {
      "any": "view" ##only return added content
    }
  ]
}"""
        url = f'{self.API_BASE_URL}/rbac/permission'
        headers = {
            'accept': 'application/json',
            'Content-Type': 'application/json'
        }
        params = {
            'org_id': f'{self.org_id}',
            'api_key': f'{self.api_key}',
            'signed_key': f'{self._secret_key}'
        }
        permissions = [{k: v} for k, v in Permission.items()]
        data = {
            "org_id": f'{self.org_id}',
            "rol_id": rol_id,
            "permissions": permissions
        }
        response = requests.post(url, headers=headers, params=params, data=json.dumps(data))
        return response.json()

    def delete_permission(self, rol_id, **Permission):
        """{
  "org_id": "4195502c85984d27ae1aceb677d99551543808625aeb11ee88069dc8f7663e88",
  "rol_id": "rol_rce_474ae9e59b3d49ce",
  "permissions": [
    {
      "user": "administration"
    },
    {
      "viewer": "administration"
    },
    {
      "maintainer": "administration"
    }
  ]
}""" #return full
        url = f'{self.API_BASE_URL}/rbac/permission'
        headers = {
            'accept': 'application/json',
            'Content-Type': 'application/json'
        }
        params = {
            'org_id': f'{self.org_id}',
            'api_key': f'{self.api_key}',
            'signed_key': f'{self._secret_key}'
        }
        permissions = [{k: v} for k, v in Permission.items()]
        data = {
            "org_id": f'{self.org_id}',
            "rol_id": rol_id,
            "permissions": permissions
        }
        response = requests.delete(url, headers=headers, params=params, data=json.dumps(data))
        return response.json()
    
class AuthLiteClient():

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

    def __init__(self, api_key, secret_key, org_id=None, API_BASE_URL="https://api.trustauthx.com", in_memory=True):
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
        self.API_BASE_URL = API_BASE_URL
        self.Roles: _Roles = _Roles(roles=self._set_edge_roles(), org_id=self.org_id, 
                                    api_key=self.api_key, signed_key=self.signed_key, 
                                    secret_key=self.secret_key, API_BASE_URL=self.API_BASE_URL,
                                    InMemory=in_memory)

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
        url = f"{self.API_BASE_URL}/api/user/me/settings/"
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
        url = f"{self.API_BASE_URL}/api/user/me/widget/re-auth/token"
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
        url = f'{self.API_BASE_URL}/api/user/me/auth/data'
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
        url = f'{self.API_BASE_URL}/api/user/me/data'
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
        url = f'{self.API_BASE_URL}/api/user/me/access/token/'
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
        url = f'{self.API_BASE_URL}/api/user/me/auth/validate/token'
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
        url = f'{self.API_BASE_URL}/api/user/me/token/'
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
        
    def _set_edge_roles(self) -> list:
        return []


