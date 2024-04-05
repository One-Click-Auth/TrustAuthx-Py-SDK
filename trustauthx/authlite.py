import json
import sqlite3
import threading
from dataclasses import asdict
from functools import wraps
from lib2to3.pgen2.parse import ParseError

import requests
from jose import JWTError, jwt
from jose.constants import ALGORITHMS
from requests.exceptions import HTTPError

from .scheme import *


class _EdgeDBRoleQuery:
    """
    A class for querying and managing roles and permissions.

    Attributes:
        in_memory (bool): Flag indicating whether to store the roles in-memory or in a SQLite database.
        roles (Dict[str, Dict[str, str]]): A dictionary mapping role IDs to permissions (in-memory mode).
        conn (sqlite3.Connection): The SQLite database connection (database mode).
        cursor (sqlite3.Cursor): The SQLite database cursor (database mode).

    Methods:
        __init__(self, roles, in_memory=True):
            Initializes the _EdgeDBRoleQuery instance with the provided roles and storage mode.

        query(self, role_id=None, permission_key=None):
            Queries the roles and permissions based on the provided role ID and/or permission key.

        validate(self, role_id, permission_key, permission_val):
            Validates a permission value for a given role ID and permission key.

        count_roles(self):
            Returns the number of roles stored.
    """

    total_roles = 0
    roles = None

    def __init__(self, roles, in_memory=True):
        """
        Initializes the _EdgeDBRoleQuery instance.

        Args:
            roles (List[Dict[str, Dict[str, str]]]): A list of dictionaries representing roles and their permissions.
            in_memory (bool, optional): Flag indicating whether to store the roles in-memory or in a SQLite database. Defaults to True.
        """
        self.in_memory = in_memory
        if self.in_memory:
            self.__class__.roles = {
                role["rol_id"]: role["permissions"][0] for role in roles
            }
        else:
            # replace ':memory:' with your database path
            self.conn = sqlite3.connect(":memory:")
            self.cursor = self.conn.cursor()
            self.cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS roles (
                    role_id TEXT PRIMARY KEY,
                    permissions TEXT
                )
            """
            )
            for role in roles:
                for role_id, permissions in role.items():
                    self.cursor.execute(
                        "INSERT INTO roles VALUES (?, ?)", (role_id, permissions)
                    )
            self.conn.commit()
        self.count_roles()

    def query(self, role_id=None, permission_key=None):
        """
        Queries the roles and permissions based on the provided role ID and/or permission key.

        Args:
            role_id (str, optional): The role ID to query.
            permission_key (str, optional): The permission key to query.

        Returns:
            Union[Dict[str, Dict[str, str]], Dict[str, str], str, None]: The queried roles, permissions, or permission value, depending on the provided arguments.
        """
        if self.in_memory:
            if role_id and permission_key:
                return self.__class__.roles.get(role_id, {}).get(permission_key, None)
            elif role_id:
                return self.__class__.roles.get(role_id, None)
            elif permission_key:
                return {
                    role_id: permissions[permission_key]
                    for role_id, permissions in self.__class__.roles.items()
                    if permission_key in permissions
                }
            else:
                return self.__class__.roles
        else:
            if role_id and permission_key:
                self.cursor.execute(
                    "SELECT permissions FROM roles WHERE role_id = ?", (role_id,)
                )
                permissions = self.cursor.fetchone()
                if permissions:
                    return permissions[0].get(permission_key, None)
            elif role_id:
                self.cursor.execute(
                    "SELECT permissions FROM roles WHERE role_id = ?", (role_id,)
                )
                return self.cursor.fetchone()
            elif permission_key:
                self.cursor.execute("SELECT * FROM roles")
                return {
                    role_id: permissions[permission_key]
                    for role_id, permissions in self.cursor.fetchall()
                    if permission_key in permissions
                }
            else:
                self.cursor.execute("SELECT * FROM roles")
                return self.cursor.fetchall()

    def validate(self, role_id, permission_key, permission_val):
        """
        Validates a permission value for a given role ID and permission key.

        Args:
            role_id (str): The role ID to validate.
            permission_key (str): The permission key to validate.
            permission_val (str): The expected permission value to validate.

        Returns:
            bool: True if the permission value matches the expected value, False otherwise.
        """
        if self.in_memory:
            return (
                self.__class__.roles.get(role_id, {}).get(permission_key, None)
                == permission_val
            )
        else:
            self.cursor.execute(
                "SELECT permissions FROM roles WHERE role_id = ?", (role_id,)
            )
            permissions = self.cursor.fetchone()
            if permissions:
                return permissions[0].get(permission_key, None) == permission_val

    def count_roles(self):
        """
        Returns the number of roles stored.

        Returns:
            int: The number of roles stored.
        """
        if self.in_memory:
            r = len(self.__class__.roles)
            _EdgeDBRoleQuery.total_roles = r
            return r
        else:
            self.cursor.execute("SELECT COUNT(*) FROM roles")
            r = self.cursor.fetchone()[0]
            _EdgeDBRoleQuery.total_roles = r
            return r

    @classmethod
    def reinitialize_all(foreground=True):
        if foreground:
            for instance in AuthLiteClient.instances:
                instance: AuthLiteClient = instance
                instance._re_init_roles()
        else:

            def target():
                for instance in AuthLiteClient.instances:
                    instance: AuthLiteClient = instance
                    instance._re_init_roles()

            thread = threading.Thread(target=target)
            thread.start()

    @staticmethod
    def _EDGE_Wrapper(func):

        @wraps(func)
        def wrapper(*args, **kwargs):
            # Call the function
            response = func(*args, **kwargs)
            # Check for "X-EDGE"
            x_edge = response.headers.get("X-EDGE")
            if x_edge:
                if int(x_edge) != _EdgeDBRoleQuery.total_roles:
                    _EdgeDBRoleQuery.reinitialize_all()  # Add data
            return response

        return wrapper


requests.get = _EdgeDBRoleQuery._EDGE_Wrapper(requests.get)
requests.post = _EdgeDBRoleQuery._EDGE_Wrapper(requests.post)
requests.delete = _EdgeDBRoleQuery._EDGE_Wrapper(requests.delete)


class _Roles(_EdgeDBRoleQuery):
    """
    A class for managing roles and permissions in the EdgeDB system.

    Attributes:
        org_id (str): The organization ID associated with the roles.
        api_key (str): The API key for authentication.
        _secret_key (str): The secret key for JWT encoding/decoding.
        signed_key (str): The signed key for authentication.
        API_BASE_URL (str): The base URL for the API.
        roles (Dict[str, Dict[str, str]]): A dictionary mapping role IDs to permissions.

    Methods:
        get_all_roles(self):
            Retrieves all roles and their permissions from the API.

        add_role(self, name, **Permission_):
            Adds a new role with the specified name and permissions.

        delete_role(self, rol_id):
            Deletes a role with the specified role ID.

        add_permission(self, rol_id, **Permission_):
            Adds a new permission to a role with the specified role ID.

        delete_permission(self, rol_id, **Permission_):
            Deletes a permission from a role with the specified role ID.
    """

    instances = []

    def __init__(
        self,
        roles,
        org_id,
        api_key,
        signed_key,
        secret_key,
        API_BASE_URL,
        InMemory=True,
    ):
        """
        Initializes the _Roles instance.

        Args:
            roles (List[Dict[str, Dict[str, str]]]): A list of dictionaries representing roles and their permissions.
            org_id (str): The organization ID associated with the roles.
            api_key (str): The API key for authentication.
            signed_key (str): The signed key for authentication.
            secret_key (str): The secret key for JWT encoding/decoding.
            API_BASE_URL (str): The base URL for the API.
            InMemory (bool, optional): Flag indicating whether to store the roles in-memory or in a SQLite database. Defaults to True.
        """
        self.org_id = org_id
        self._api_key = api_key
        self._secret_key = secret_key
        self._signed_key = signed_key
        self.API_BASE_URL = API_BASE_URL
        self.__class__.instances.append(self)
        super().__init__(roles, in_memory=InMemory)
        print(self.__class__.roles)

    def get_all_roles(self) -> GetAllRolesResponse:
        """
        Retrieves all roles and their permissions from the API.

        Returns:
            roles_list = List[Role]: A list of Role objects representing the roles and their permissions.roles
            roles_json_list = List[dict]: A list of dict representing the roles and their permissions

        demo response ==> [
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
        url = f"{self.API_BASE_URL}/rbac/role"
        headers = {"accept": "application/json"}
        params = {
            "org_id": f"{self.org_id}",
            "api_key": f"{self._api_key}",
            "signed_key": f"{self._signed_key}",
        }
        response = requests.get(url, headers=headers, params=params)
        roles = [Role(**role_data) for role_data in response.json()]
        return GetAllRolesResponse(
            roles_list=roles, roles_json_list=[asdict(role) for role in roles]
        )

    def add_role(self, name, **Permission_) -> AddRoleResponse:
        """
        Adds a new role with the specified name and permissions.

        Args:
            name (str): The name of the new role.
            **Permission_: Keyword arguments representing the permissions to be added to the new role.

        Returns:
            AddRoleResponse: An AddRoleResponse object representing the newly created role.

        demo response ==> {
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
        url = f"{self.API_BASE_URL}/rbac/role"
        headers = {"accept": "application/json", "Content-Type": "application/json"}
        params = {
            "org_id": f"{self.org_id}",
            "api_key": f"{self._api_key}",
            "signed_key": f"{self._signed_key}",
        }
        permissions = [{k: v} for k, v in Permission_.items()]
        data = {"org_id": f"{self.org_id}", "name": name, "permissions": permissions}
        response = requests.post(
            url, headers=headers, params=params, data=json.dumps(data)
        )
        role_data = response.json()
        permissions = [Permission(**p) for p in role_data.get("permissions", [])]
        return AddRoleResponse(
            org_id=role_data.get("org_id"),
            rol_id=role_data.get("rol_id"),
            name=role_data.get("name"),
            permissions=[p.__dict__ for p in permissions],
        )

    def delete_role(self, rol_id) -> DeleteRoleResponse:
        """
        Deletes a role with the specified role ID.

        Args:
            rol_id (str): The ID of the role to be deleted.

        Returns:
            DeleteRoleResponse: A DeleteRoleResponse object representing the deleted role.

        demo response ==> {
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
        url = f"{self.API_BASE_URL}/rbac/role"
        headers = {"accept": "application/json", "Content-Type": "application/json"}
        params = {
            "org_id": f"{self.org_id}",
            "api_key": f"{self._api_key}",
            "signed_key": f"{self._signed_key}",
        }
        data = {"org_id": f"{self.org_id}", "rol_id": rol_id}
        response = requests.delete(
            url, headers=headers, params=params, data=json.dumps(data)
        )
        role_data = response.json()
        permissions = [Permission(**p) for p in role_data.get("permissions", [])]
        return DeleteRoleResponse(
            org_id=role_data.get("org_id"),
            rol_id=role_data.get("rol_id"),
            name=role_data.get("name"),
            permissions=[p.__dict__ for p in permissions],
        )

    def add_permission(
        self, rol_id, foreground=False, **Permission_
    ) -> AddPermissionResponse:
        """
        Adds a new permission to a role with the specified role ID.

        Args:
            rol_id (str): The ID of the role to which the permission should be added.
            **Permission_: Keyword arguments representing the permissions to be added.

        Returns:
            AddPermissionResponse: An AddPermissionResponse object representing the added permission.

        demo response ==> {
          "org_id": "4195502c85984d27ae1aceb677d99551543808625aeb11ee88069dc8f7663e88",
          "rol_id": "rol_rce_474ae9e59b3d49ce",
          "permissions": [
            {
              "any": "view" ##only return added content
            }
          ]
        }"""
        url = f"{self.API_BASE_URL}/rbac/permission"
        headers = {"accept": "application/json", "Content-Type": "application/json"}
        params = {
            "org_id": f"{self.org_id}",
            "api_key": f"{self._api_key}",
            "signed_key": f"{self._signed_key}",
        }
        permissions = [{k: v} for k, v in Permission_.items()]
        data = {
            "org_id": f"{self.org_id}",
            "rol_id": rol_id,
            "permissions": permissions,
        }
        response = requests.post(
            url, headers=headers, params=params, data=json.dumps(data)
        )
        response_data = response.json()
        permissions = [Permission(**{k: v}) for k, v in permissions.items()]
        self.reinitialize_all(foreground)
        return AddPermissionResponse(
            org_id=response_data.get("org_id"),
            rol_id=response_data.get("rol_id"),
            permissions=[p.__dict__ for p in permissions],
        )

    def delete_permission(
        self, rol_id, foreground=False, **Permission_
    ) -> DeletePermissionResponse:
        """
        Deletes a permission from a role with the specified role ID.

        Args:
            rol_id (str): The ID of the role from which the permission should be deleted.
            **Permission_: Keyword arguments representing the permissions to be deleted.

        Returns:
            DeletePermissionResponse: A DeletePermissionResponse object representing the role with the deleted permission.

        demo response ==> {
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
        }"""  # return full
        url = f"{self.API_BASE_URL}/rbac/permission"
        headers = {"accept": "application/json", "Content-Type": "application/json"}
        params = {
            "org_id": f"{self.org_id}",
            "api_key": f"{self._api_key}",
            "signed_key": f"{self._signed_key}",
        }
        permissions = [{k: v} for k, v in Permission_.items()]
        data = {
            "org_id": f"{self.org_id}",
            "rol_id": rol_id,
            "permissions": permissions,
        }
        response = requests.delete(
            url, headers=headers, params=params, data=json.dumps(data)
        )
        self.reinitialize_all(foreground)
        return response.json()


class AuthLiteClient:
    instances = []
    """
    AuthLiteClient is a Python client for the TrustAuthX authentication service.

    Attributes:
        api_key (str): The API key used for authentication.
        secret_key (str): The secret key used for JWT encoding.
        org_id (str): The organization ID for generating authentication URLs.
        signed_key (str): The signed key used for generating URLs.
        jwt_encode (Callable): A function for encoding JSON Web Tokens (JWTs).
        jwt_decode (Callable): A function for decoding JSON Web Tokens (JWTs).
        API_BASE_URL (str): The base URL for the API.
        Roles (_Roles): An instance of the _Roles class for managing roles and permissions.

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

        access: str
        refresh: str
        state: bool

    def __init__(
        self,
        api_key,
        secret_key,
        org_id=None,
        API_BASE_URL="https://api.trustauthx.com",
        in_memory=True,
    ):
        """
        Initializes the AuthLiteClient instance.

        Args:
            api_key (str): The API key used for authentication.
            secret_key (str): The secret key used for JWT encoding.
            org_id (str, optional): The organization ID for generating authentication URLs.
            API_BASE_URL (str, optional): The base URL for the API. Defaults to "https://api.trustauthx.com".
            in_memory (bool, optional): Flag indicating whether to store the roles in-memory or in a SQLite database. Defaults to True (ie. in-memory).

        """
        self.jwt_encode = lambda key, data: jwt.encode(
            data, key=key, algorithm=ALGORITHMS.HS256
        )
        self.jwt_decode = lambda key, data: jwt.decode(
            str(data), key=key, algorithms=ALGORITHMS.HS256
        )
        self._secret_key = secret_key
        self._api_key = api_key
        self.org_id = org_id
        self._signed_key = self.jwt_encode(
            key=self._secret_key, data={"api_key": self._api_key}
        )
        self.API_BASE_URL = API_BASE_URL
        self.in_memory = in_memory
        self.Roles: _Roles = _Roles(
            roles=self._set_edge_roles(),
            org_id=self.org_id,
            api_key=self._api_key,
            signed_key=self._signed_key,
            secret_key=self._secret_key,
            API_BASE_URL=self.API_BASE_URL,
            InMemory=in_memory,
        )
        self.__class__.instances.append(self)

    def generate_url(self) -> str:
        """
        Generates an authentication URL for the given organization.

        Returns:
            str: The generated authentication URL.

        Raises:
            ValueError: If org_id is not provided.
        """
        # Generate an authentication url for the given org
        if self.org_id:
            return f"https://app.trustauthx.com/widget/login/?org_id={self.org_id}"
        else:
            raise ValueError("must provide org_id")

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
        headers = {"accept": "application/json"}
        params = {
            "AccessToken": access_token,
            "api_key": self._api_key,
            "signed_key": self._signed_key,
            "url": url,
        }
        url = f"{self.API_BASE_URL}/api/user/me/settings/"
        req = requests.Request("GET", url, params=params, headers=headers).prepare()
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
            "api_key": self._api_key,
            "signed_key": self._signed_key,
        }
        headers = {"accept": "application/json"}
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            rtn = self.jwt_decode(self._secret_key, response.json())
            sub = json.loads(rtn["sub"])
            rtn.pop("sub")
            rtn["email"] = sub["email"]
            rtn["uid"] = sub["uid"]
            return rtn
        else:
            raise HTTPError(
                "Request failed with status code : {} \n this code contains a msg : {}".format(
                    response.status_code, response.text
                )
            )

    def get_user(self, token, return_class=False) -> User | dict:
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
        url = f"{self.API_BASE_URL}/api/user/me/auth/data"
        headers = {"accept": "application/json"}
        params = {
            "UserToken": token,
            "api_key": self._api_key,
            "signed_key": self._signed_key,
        }
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            rtn = self.jwt_decode(self._secret_key, response.json())
            sub = json.loads(rtn["sub"])
            rtn.pop("sub")
            rtn["email"] = sub["email"]
            rtn["uid"] = sub["uid"]
            if not return_class:
                return User(rtn).to_dict()
            else:
                return User(rtn)
        else:
            raise HTTPError(
                "Request failed with status code : {} \n this code contains a msg : {}".format(
                    response.status_code, response.text
                )
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
        url = f"{self.API_BASE_URL}/api/user/me/data"
        headers = {"accept": "application/json"}
        params = {
            "AccessToken": AccessToken,
            "api_key": self._api_key,
            "signed_key": self._signed_key,
        }
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            rtn = self.jwt_decode(self._secret_key, response.json())
            return rtn
        else:
            raise HTTPError(
                "Request failed with status code : {} \n this code contains a msg : {}".format(
                    response.status_code, response.text
                )
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
        url = f"{self.API_BASE_URL}/api/user/me/access/token/"
        headers = {"accept": "application/json"}
        params = {
            "RefreshToken": refresh_token,
            "api_key": self._api_key,
            "signed_key": self._signed_key,
        }
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            raise HTTPError(
                "Request failed with status code : {} \n this code contains a msg : {}".format(
                    response.status_code, response.text
                )
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
        url = f"{self.API_BASE_URL}/api/user/me/auth/validate/token"
        headers = {"accept": "application/json"}
        params = {
            "AccessToken": access_token,
            "api_key": self._api_key,
            "signed_key": self._signed_key,
        }
        response = requests.get(url, headers=headers, params=params)
        return response.status_code == 200

    def revoke_token(
        self,
        AccessToken: str = None,
        RefreshToken: str = None,
        revoke_all_tokens: bool = False,
    ) -> bool:
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
        url = f"{self.API_BASE_URL}/api/user/me/token/"
        headers = {"accept": "application/json"}
        if not AccessToken and not RefreshToken:
            raise AttributeError("must provide either AccessToken or RefreshToken")
        tt = True if AccessToken else False
        t = AccessToken if AccessToken else RefreshToken
        params = {
            "Token": t,
            "api_key": self._api_key,
            "signed_key": self._signed_key,
            "AccessToken": tt,
            "SpecificTokenOnly": not revoke_all_tokens,
        }
        response = requests.delete(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            raise HTTPError(
                "Request failed with status code : {} \n this code contains a msg : {}".format(
                    response.status_code, response.text
                )
            )

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
                    d.access = new_tokens["access_token"]
                    d.refresh = new_tokens["refresh_token"]
                return d
            else:
                d.state = True
                d.access = access_token
                d.refresh = refresh_token
                return d
        except:
            raise HTTPError("both tokens are invalid login again")

    def _set_edge_roles(self) -> list:
        # self.Roles
        url = f"{self.API_BASE_URL}/rbac/role"
        headers = {"accept": "application/json"}
        params = {
            "org_id": f"{self.org_id}",
            "api_key": f"{self._api_key}",
            "signed_key": f"{self._signed_key}",
        }
        response = requests.get(url, headers=headers, params=params)
        roles = [Role(**role_data) for role_data in response.json()]
        roles = GetAllRolesResponse(
            roles_list=roles, roles_json_list=[asdict(role) for role in roles]
        )
        # print(roles.roles_json_list)
        return roles.roles_json_list

    def _re_init_roles(self) -> _Roles:
        self.Roles: _Roles = _Roles(
            roles=self._set_edge_roles(),
            org_id=self.org_id,
            api_key=self._api_key,
            signed_key=self._signed_key,
            secret_key=self._secret_key,
            API_BASE_URL=self.API_BASE_URL,
            InMemory=self.in_memory,
        )
        return self.Roles

    def attach_role(
        self,
        uid: str,
        rol_ids: str | list,
        signoff_session_and_assign=False,
        refresh_token=None,
        access_token=None,
        return_class: bool = False,
    ) -> dict | SignOffSessionReplace:
        """
        Attaches a role to a user.

        Args:
            uid (str): The user ID to attach the role to.
            rol_ids (str | list): The ID(s) of the role(s) to attach.
            signoff_session_and_assign (bool, optional): Whether to sign off the session and assign. Default is False.
            refresh_token (str, optional): The refresh token for authentication.
            access_token (str, optional): The access token for authentication.
            return_class (bool, optional): Whether to return a class instance. Default is False.

        Returns:
            dict | SignOffSessionReplace: The response from the API, or a class instance if return_class is True.

        Raises:
            ParseError: If signoff_session_and_assign is True but refresh_token or access_token is not provided.
        """
        if signoff_session_and_assign:
            if not refresh_token or not access_token:
                raise ParseError(
                    "must parse refresh_token and access_token if signoff_session_and_assign is true"
                )
        url = f"{self.API_BASE_URL}/rbac/assign/permission"
        headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
        }
        params = {
            "org_id": self.org_id,
            "api_key": self._api_key,
            "signed_key": self._signed_key,
        }
        rols = []
        if isinstance(rol_ids) == str:
            rols.append(rol_ids)
        elif isinstance(rol_ids) == list:
            rols = [i for i in rol_ids]
        else:
            raise TypeError()
        data = {
            "uid": uid,
            "rol_id": rol_ids,
            "inplace": [],
            "signoff_session_and_assign": signoff_session_and_assign,
            "AccessToken": access_token,
            "RefreshToken": refresh_token,
        }
        response = requests.post(url, headers=headers, params=params, json=data)
        if signoff_session_and_assign:
            return response.json()
        else:
            if return_class:
                return SignOffSessionReplace(response.json())
            else:
                return SignOffSessionReplace(response.json()).to_dict()

    def remove_role(
        self,
        uid: str,
        rol_ids: str | list,
        signoff_session_and_assign=False,
        refresh_token=None,
        access_token=None,
        return_class: bool = False,
    ) -> dict | SignOffSessionReplace:
        """
        Removes a role from a user.

        Args:
            uid (str): The user ID to remove the role from.
            rol_ids (str | list): The ID(s) of the role(s) to remove.
            signoff_session_and_assign (bool, optional): Whether to sign off the session and assign. Default is False.
            refresh_token (str, optional): The refresh token for authentication.
            access_token (str, optional): The access token for authentication.
            return_class (bool, optional): Whether to return a class instance. Default is False.

        Returns:
            dict | SignOffSessionReplace: The response from the API, or a class instance if return_class is True.

        Raises:
            ParseError: If signoff_session_and_assign is True but refresh_token or access_token is not provided.
        """
        if signoff_session_and_assign:
            if not refresh_token or not access_token:
                raise ParseError(
                    "must parse refresh_token and access_token if signoff_session_and_assign is true"
                )
        url = f"{self.API_BASE_URL}/rbac/assign/permission"
        headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
        }
        params = {
            "org_id": self.org_id,
            "api_key": self._api_key,
            "signed_key": self._signed_key,
        }
        rols = []
        if isinstance(rol_ids) == str:
            rols.append(rol_ids)
        elif isinstance(rol_ids) == list:
            rols = [i for i in rol_ids]
        else:
            raise TypeError()
        data = {
            "uid": uid,
            "rol_id": [],
            "inplace": rol_ids,
            "signoff_session_and_assign": signoff_session_and_assign,
            "AccessToken": access_token,
            "RefreshToken": refresh_token,
        }
        response = requests.post(url, headers=headers, params=params, json=data)
        if signoff_session_and_assign:
            return response.json()
        else:
            if return_class:
                return SignOffSessionReplace(response.json())
            else:
                return SignOffSessionReplace(response.json()).to_dict()

    def update_role(
        self,
        uid: str,
        rol_ids_to_add: str | list,
        rol_ids_to_remove: str | list,
        signoff_session_and_assign=False,
        refresh_token=None,
        access_token=None,
        return_class: bool = False,
    ) -> dict | SignOffSessionReplace:
        """
        Updates a user's roles by adding and/or removing roles.

        Args:
            uid (str): The user ID to update roles for.
            rol_ids_to_add (str | list): The ID(s) of the role(s) to add.
            rol_ids_to_remove (str | list): The ID(s) of the role(s) to remove.
            signoff_session_and_assign (bool, optional): Whether to sign off the session and assign. Default is False.
            refresh_token (str, optional): The refresh token for authentication.
            access_token (str, optional): The access token for authentication.
            return_class (bool, optional): Whether to return a class instance. Default is False.

        Returns:
            dict | SignOffSessionReplace: The response from the API, or a class instance if return_class is True.

        Raises:
            ParseError: If signoff_session_and_assign is True but refresh_token or access_token is not provided.
        """
        if signoff_session_and_assign:
            if not refresh_token or not access_token:
                raise ParseError(
                    "must parse refresh_token and access_token if signoff_session_and_assign is true"
                )
        url = f"{self.API_BASE_URL}/rbac/assign/permission"
        headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
        }
        params = {
            "org_id": self.org_id,
            "api_key": self._api_key,
            "signed_key": self._signed_key,
        }
        rols_add = []
        if isinstance(rol_ids_to_add) == str:
            rols_add.append(rol_ids_to_add)
        elif isinstance(rol_ids_to_add) == list:
            rols_add = [i for i in rol_ids_to_add]
        else:
            raise TypeError()
        rols_rem = []
        if isinstance(rol_ids_to_remove) == str:
            rols_rem.append(rol_ids_to_remove)
        elif isinstance(rol_ids_to_remove) == list:
            rols_rem = [i for i in rol_ids_to_remove]
        else:
            raise TypeError()
        data = {
            "uid": uid,
            "rol_id": rols_add,
            "inplace": rols_rem,
            "signoff_session_and_assign": signoff_session_and_assign,
            "AccessToken": access_token,
            "RefreshToken": refresh_token,
        }
        response = requests.post(url, headers=headers, params=params, json=data)
        if signoff_session_and_assign:
            return response.json()
        else:
            if return_class:
                return SignOffSessionReplace(response.json())
            else:
                return SignOffSessionReplace(response.json()).to_dict()
