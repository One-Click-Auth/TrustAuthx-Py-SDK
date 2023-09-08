from pycnic.core import WSGI, Handler
from pycnic.errors import HTTP_400, HTTP_401
from trustauthx.authlite import AuthLiteClient

class AuthHandler(Handler):
    def __init__(self):
        self.auth_lite_client = AuthLiteClient(api_key="f28ffe7f2e4a47d6a796b0c2df073aeeAVVQBFSSCXIQWNQIEPBI", 
                                               secret_key="8ad9741c8fd5a8f286fc34eba21e0871e63dff3dd67e3ea3a1b43077db9531f7", 
                                               org_id="c3621ed40ccc4fca955779fab8f776c921e8865e439211ee88069dc8f7663e88")

    def auth_client(self):
        return self.auth_lite_client

    def on_request(self, req, rsp):
        access_token = req.session.get("access_token")
        refresh_token = req.session.get("refresh_token")

        try:
            a = self.auth_client().validate_token_set(access_token=access_token, refresh_token=refresh_token)
            if not a.state:
                req.session["access_token"] = a.access
                req.session["refresh_token"] = a.refresh
                rsp.text = "Token Regenerated refresh Token Valid"
            else:
                rsp.text = "Access Token Valid"
        except Exception as e:
            # You might need to handle the redirect response here
            raise HTTP_401("Unauthorized")

class Root(AuthHandler):
    def get(self):
        return "Redirecting..."  # You might need to implement the redirect here

class User(AuthHandler):
    def get(self, code):
        try:
            user = self.auth_client().get_user(code)
            self.req.session["access_token"] = user['access_token']
            self.req.session["refresh_token"] = user['refresh_token']
            return {"user": user}
        except:
            raise HTTP_400("Bad Request")

class UserUpdate(AuthHandler):
    def get(self):
        access_token = self.req.session.get("access_token")
        url = self.auth_client().generate_edit_user_url(access_token, url="http://127.0.0.1:3535/re-auth")
        raise HTTP_400("Redirect")  # You might need to implement the redirect here

class ReAuth(AuthHandler):
    def get(self, code):
        try:
            user = self.auth_client().re_auth(code)
            self.req.session["access_token"] = user['access_token']
            self.req.session["refresh_token"] = user['refresh_token']
            return {"user": user}
        except:
            raise HTTP_400("Redirect")  # You might need to implement the redirect here

class ValidateToken(AuthHandler):
    def get(self):
        return self.on_request(self.req, self.rsp)

class SignOut(AuthHandler):
    def get(self):
        try:
            self.auth_client().revoke_token(AccessToken=self.req.session.get("access_token"), revoke_all_tokens=True)
            return "Tokens revoked"
        except:
            raise HTTP_400("Redirect")  # You might need to implement the redirect here

class SemiSignOut(AuthHandler):
    def get(self):
        try:
            self.auth_client().revoke_token(AccessToken=self.req.session.get("access_token"))
            return "Access token revoked"
        except:
            raise HTTP_400("Redirect")  # You might need to implement the redirect here

app = WSGI([("/", Root), ("/user/(.*)", User), ("/user-update", UserUpdate),
            ("/re-auth/(.*)", ReAuth), ("/validate-token", ValidateToken),
            ("/sign-out", SignOut), ("/semi-sign-out", SemiSignOut)])

if __name__ == "__main__":
    from wsgiref.simple_server import make_server
    server = make_server("127.0.0.1", 3535, app)
    server.serve_forever()
