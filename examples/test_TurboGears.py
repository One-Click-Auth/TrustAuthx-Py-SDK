from tg import expose, TGController, AppConfig, redirect, validate, request, response
from beaker.middleware import SessionMiddleware
from trustauthx.authlite import AuthLiteClient

class RootController(TGController):
    
    auth_lite_client = AuthLiteClient(api_key="f28ffe7f2e4a47d6a796b0c2df073aeeAVVQBFSSCXIQWNQIEPBI", 
                        secret_key="8ad9741c8fd5a8f286fc34eba21e0871e63dff3dd67e3ea3a1b43077db9531f7", 
                        org_id="c3621ed40ccc4fca955779fab8f776c921e8865e439211ee88069dc8f7663e88")
    
    def get_auth_(self):
        access_token = request.environ['beaker.session'].get("access_token")
        refresh_token = request.environ['beaker.session'].get("refresh_token")
        try:
            a = self.auth_lite_client.validate_token_set(access_token=access_token, refresh_token=refresh_token)
            if not a.state:
                request.environ['beaker.session']["access_token"] = a.access
                request.environ['beaker.session']["refresh_token"] = a.refresh
                t="Token Regenerated refresh Token Valid" 
            else:t="Access Token Valid"
            return t
        except Exception as e:
            return redirect(self.auth_lite_client.generate_url())
    
    @expose()
    def index(self):
        return redirect(self.auth_lite_client.generate_url())
    
    @expose('json')
    def user(self, code=None, AccessToken=request.environ['beaker.session'].get("access_token")):
        acto = AccessToken
        if acto: return {"user": self.auth_lite_client.get_user_data(acto)}
        try:
            user = self.auth_lite_client.get_user(code)
            request.environ['beaker.session']["access_token"] = user['access_token']
            request.environ['beaker.session']["refresh_token"] = user['refresh_token']
            return {"user": user}
        except:
            response.status = 400
            return {"error": "Bad Request"}
    
    @expose()
    def user_update(self):
        try:
            access_token = request.environ['beaker.session'].get("access_token")
            return redirect(self.auth_lite_client.generate_edit_user_url(access_token, url ="http://127.0.0.1:3535/re-auth"))
        except:
            response.status = 400
            return {"error": "Bad Request"}
    
    @expose('json')
    def re_auth(self, code=None):
        try:
            user = self.auth_lite_client.re_auth(code)
            request.environ['beaker.session']["access_token"] = user['access_token']
            request.environ['beaker.session']["refresh_token"] = user['refresh_token']
            return {"user": user}
        except:
            return redirect("http://127.0.0.1:3535/validate-token")
    
    @expose('json')
    def validate_token(self):
        token_validator = self.get_auth_()
        return token_validator
    
    def revoketokens(self):
        try:
            return self.auth_lite_client.revoke_token(AccessToken=request.environ['beaker.session'].get("access_token"), revoke_all_tokens=True)
        except:
            return redirect(self.auth_lite_client.generate_url())
    
    def revokeAccesstokens(self):
        try:
            return self.auth_lite_client.revoke_token(AccessToken=request.environ['beaker.session'].get("access_token"))
        except:
            return redirect(self.auth_lite_client.generate_url())
    
    @expose('json')
    def sign_out(self):
        r = self.revoketokens()
        return r
    
    @expose('json')
    def semi_sign_out(self):
        r = self.revokeAccesstokens()
        return r

config = AppConfig(minimal=True, root_controller=RootController())
config.renderers.append('json')
config.serve_static = True
config.paths['static_files'] = 'public'
app = config.make_wsgi_app()

session_opts = {
    'session.type': 'memory',
    'session.cookie_expires': 300,
    'session.auto': True
}
app = SessionMiddleware(app, session_opts)

if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    httpd = make_server('', 3535, app)
    httpd.serve_forever()
