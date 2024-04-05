from dataclasses import asdict, dataclass
from typing import Dict, List, Union


@dataclass
class Permission:
    """
    A class representing a permission object.
    """

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def to_dict(self):
        return asdict(self)


@dataclass
class Role:
    """
    A class representing a role object.

    Attributes:
        org_id (str): The organization ID associated with the role.
        rol_id (str): The unique identifier of the role.
        name (str): The name of the role.
        permissions (List[Permission]): A list of permissions associated with the role.
    """

    org_id: str
    rol_id: str
    name: str
    permissions: List[Permission]

    def to_dict(self):
        return asdict(self)


@dataclass
class GetAllRolesResponse:
    roles_list: List[Role]
    roles_json_list: List[Dict[str, Union[str, List[Dict[str, str]]]]]

    def to_dict(self):
        return asdict(self)


@dataclass
class AddRoleResponse:
    org_id: str
    rol_id: str
    name: str
    permissions: List[Permission]

    def to_dict(self):
        return asdict(self)


@dataclass
class DeleteRoleResponse:
    org_id: str
    rol_id: str
    name: str
    permissions: List[Permission]

    def to_dict(self):
        return asdict(self)


@dataclass
class AddPermissionResponse:
    org_id: str
    rol_id: str
    permissions: List[Dict[str, str]]

    def to_dict(self):
        return asdict(self)


@dataclass
class DeletePermissionResponse:
    org_id: str
    rol_id: str
    permissions: List[Permission]

    def to_dict(self):
        return asdict(self)


@dataclass
class User:
    iss: str
    jti: str
    access_token: str
    type: str
    exp: float
    refresh_token: str
    refresh_exp: int
    scope: List[str]
    img: str
    name: str
    iat: int
    email: str
    uid: str

    def to_dict(self):
        return asdict(self)


@dataclass
class SignOffSessionReplace:
    uid: str
    access_token: str
    refresh_token: str
    role: List[str]

    def to_dict(self):
        return asdict(self)


"""# Demo data
demo_get_all_roles_response = GetAllRolesResponse(roles=[
    {
        "org_id": "4195502c85984d27ae1aceb677d99551543808625aeb11ee88069dc8f7663e88",
        "rol_id": "rol_gCD_ebc6f7715bb14554",
        "name": "string",
        "permissions": [
            {
                "name": "user",
                "value": "administration"
            }
        ]
    },
    # ... (other roles omitted for brevity)
])

demo_add_role_response = AddRoleResponse(
    org_id="4195502c85984d27ae1aceb677d99551543808625aeb11ee88069dc8f7663e88",
    rol_id="rol_rce_474ae9e59b3d49ce",
    name="string",
    permissions=[
        Permission(name="user", value="administration"),
        Permission(name="viewer", value="administration"),
        Permission(name="maintainer", value="administration")
    ]
)

demo_delete_role_response = DeleteRoleResponse(
    org_id="4195502c85984d27ae1aceb677d99551543808625aeb11ee88069dc8f7663e88",
    rol_id="rol_YHV_78ae9006bcaa4c77",
    name="string",
    permissions=[
        Permission(name="user", value="administration"),
        Permission(name="viewer", value="administration"),
        Permission(name="maintainer", value="administration")
    ]
)

demo_add_permission_response = AddPermissionResponse(
    org_id="4195502c85984d27ae1aceb677d99551543808625aeb11ee88069dc8f7663e88",
    rol_id="rol_rce_474ae9e59b3d49ce",
    permissions=[
        {
            "name": "any",
            "value": "view"
        }
    ]
)

demo_delete_permission_response = DeletePermissionResponse(
    org_id="4195502c85984d27ae1aceb677d99551543808625aeb11ee88069dc8f7663e88",
    rol_id="rol_rce_474ae9e59b3d49ce",
    permissions=[
        Permission(name="user", value="administration"),
        Permission(name="viewer", value="administration"),
        Permission(name="maintainer", value="administration")
    ]
)
"""

# class Permission:
#     def __init__(self, **kwargs):
#         for key, value in kwargs.items():
#             setattr(self, key, value)

# role_data = {
#     "permissions": [
#         {"read": "true", "write": "false"},
#         {"execute": "true"}
#     ]
# }

# permissions = [Permission(**p) for p in role_data.get("permissions", [])]

# for permission in permissions:
#     print(permission.__dict__)
