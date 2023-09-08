import cherrypy
from trustauthx.authlite import AuthLiteClient

class Root(object):
    
    _cp_config = {
        'tools.sessions.on': True,
        'tools.sessions.timeout': 60,
    }
    
    auth_lite_client = AuthLiteClient(api_key="f28ffe7f2e4a47d6a796b0c2df073aeeAVVQBFSSCXIQWNQIEPBI", 
                        secret_key="8ad9741c8fd5a8f286fc34eba21e0871e63dff3dd67e3ea3a1b43077db9531f7", 
                        org_id="c3621ed40ccc4fca955779fab8f776c921e8865e439211ee88069dc8f7663e88")
    
    def get_auth_(self):
        access_token = cherrypy.session.get("access_token")
        refresh_token = cherrypy.session.get("refresh_token")
        try:
            a = self.auth_lite_client.validate_token_set(access_token=access_token, refresh_token=refresh_token)
            if not a.state:
                cherrypy.session["access_token"] = a.access
                cherrypy.session["refresh_token"] = a.refresh
                t="Token Regenerated refresh Token Valid" 
            else:t="Access Token Valid"
            return t
        except Exception as e:
            raise cherrypy.HTTPRedirect(self.auth_lite_client.generate_url())
    
    @cherrypy.expose
    def index(self):
        raise cherrypy.HTTPRedirect(self.auth_lite_client.generate_url())
    
    @cherrypy.expose
    def user(self, code=None):
        try:
            user = self.auth_lite_client.get_user(code)
            cherrypy.session["access_token"] = user['access_token']
            cherrypy.session["refresh_token"] = user['refresh_token']
            return {"user": user}
        except:
            raise cherrypy.HTTPError(400)
    
    @cherrypy.expose
    def user_update(self):
        try:
            access_token = cherrypy.session.get("access_token")
            raise cherrypy.HTTPRedirect(self.auth_lite_client.generate_edit_user_url(access_token, url ="http://127.0.0.1:3535/re-auth"))
        except:
            raise cherrypy.HTTPError(400)
    
    @cherrypy.expose
    def re_auth(self, code=None):
        try:
            user = self.auth_lite_client.re_auth(code)
            cherrypy.session["access_token"] = user['access_token']
            cherrypy.session["refresh_token"] = user['refresh_token']
            return {"user": user}
        except:
            raise cherrypy.HTTPRedirect("http://127.0.0.1:3535/validate-token")
    
    @cherrypy.expose
    def validate_token(self):
        token_validator = self.get_auth_()
        return token_validator
    
    def revoketokens(self):
        try:
            return self.auth_lite_client.revoke_token(AccessToken=cherrypy.session.get("access_token"), revoke_all_tokens=True)
        except:
            raise cherrypy.HTTPRedirect(self.auth_lite_client.generate_url())
    
    def revokeAccesstokens(self):
        try:
            return self.auth_lite_client.revoke_token(AccessToken=cherrypy.session.get("access_token"))
        except:
            raise cherrypy.HTTPRedirect(self.auth_lite_client.generate_url())
    
    @cherrypy.expose
    def sign_out(self):
        r = self.revoketokens()
        return r
    
    @cherrypy.expose
    def semi_sign_out(self):
        r = self.revokeAccesstokens()
        return r

cherrypy.quickstart(Root())
