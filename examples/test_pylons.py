from pylons import request, response, session, tmpl_context as c, url
from pylons.controllers.util import abort, redirect_to

from trustauthx.authlite import AuthLiteClient

auth_lite_client = AuthLiteClient(api_key="f28ffe7f2e4a47d6a796b0c2df073aeeAVVQBFSSCXIQWNQIEPBI", 
                                  secret_key="8ad9741c8fd5a8f286fc34eba21e0871e63dff3dd67e3ea3a1b43077db9531f7", 
                                  org_id="c3621ed40ccc4fca955779fab8f776c921e8865e439211ee88069dc8f7663e88")

class RootController(BaseController):
    def index(self):
        # You might need to implement the redirect here
        return "Redirecting..."

    def auth_client(self):
        return auth_lite_client

    def get_auth(self):
        access_token = session.get("access_token")
        refresh_token = session.get("refresh_token")

        try:
            a = self.auth_client().validate_token_set(access_token=access_token, refresh_token=refresh_token)
            if not a.state:
                session["access_token"] = a.access
                session["refresh_token"] = a.refresh
                return "Token Regenerated refresh Token Valid"
            else:
                return "Access Token Valid"
        except Exception as e:
            # You might need to handle the redirect response here
            abort(401)

    def user(self, code):
        acto = session.get("access_token")
        if acto: return {"user": auth_lite_client.get_user_data(acto)}
        try:
            user = self.auth_client().get_user(code)
            session["access_token"] = user['access_token']
            session["refresh_token"] = user['refresh_token']
            return {"user": user}
        except:
            abort(400)

    def user_update(self):
        access_token = session.get("access_token")
        url = self.auth_client().generate_edit_user_url(access_token, url="http://127.0.0.1:3535/re-auth")
        # You might need to implement the redirect here
        abort(400)

    def re_auth(self, code):
        try:
            user = self.auth_client().re_auth(code)
            session["access_token"] = user['access_token']
            session["refresh_token"] = user['refresh_token']
            return {"user": user}
        except:
            # You might need to implement the redirect here
            abort(400)

    def validate_token(self):
        return self.get_auth()

    def sign_out(self):
        try:
            self.auth_client().revoke_token(AccessToken=session.get("access_token"), revoke_all_tokens=True)
            return "Tokens revoked"
        except:
            # You might need to implement the redirect here
            abort(400)

    def semi_sign_out(self):
        try:
            self.auth_client().revoke_token(AccessToken=session.get("access_token"))
            return "Access token revoked"
        except:
            # You might need to implement the redirect here
            abort(400)


#  config/routing.py:

from routes import Mapper

def make_map(config):
    map = Mapper(directory=config['pylons.paths']['controllers'],
                 always_scan=config['debug'])
    
    map.connect('root', '/', controller='root', action='index')
    map.connect('auth', '/validate-token', controller='root', action='validate_token')
    map.connect('user', '/user/{code}', controller='root', action='user')
    map.connect('user_update', '/user-update', controller='root', action='user_update')
    map.connect('re_auth', '/re-auth/{code}', controller='root', action='re_auth')
    map.connect('sign_out', '/sign-out', controller='root', action='sign_out')
    map.connect('semi_sign_out', '/semi-sign-out', controller='root', action='semi_sign_out')

    return map
