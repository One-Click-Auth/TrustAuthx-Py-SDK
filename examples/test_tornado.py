import tornado.ioloop
import tornado.web
from tornado.options import define, options, parse_command_line
from beaker.middleware import SessionMiddleware
from trustauthx.authlite import AuthLiteClient

define("port", default=3535, help="run on the given port", type=int)

auth_lite_client = AuthLiteClient(api_key="f28ffe7f2e4a47d6a796b0c2df073aeeAVVQBFSSCXIQWNQIEPBI", 
                        secret_key="8ad9741c8fd5a8f286fc34eba21e0871e63dff3dd67e3ea3a1b43077db9531f7", 
                        org_id="c3621ed40ccc4fca955779fab8f776c921e8865e439211ee88069dc8f7663e88")

def get_auth_(self):
    session = self.session
    access_token = session.get("access_token")
    refresh_token = session.get("refresh_token")
    try:
        a = auth_lite_client.validate_token_set(access_token=access_token, refresh_token=refresh_token)
        if not a.state:
            session["access_token"] = a.access
            session["refresh_token"] = a.refresh
            t="Token Regenerated refresh Token Valid" 
        else:t="Access Token Valid"
        return t
    except Exception as e:
        self.redirect(auth_lite_client.generate_url())

class BaseHandler(tornado.web.RequestHandler):
    
    def prepare(self):
        self.session = self.application.session
        
    def on_finish(self):
        self.session.save()

class RootHandler(BaseHandler):
    
    def get(self):
        self.redirect(auth_lite_client.generate_url())

class GetUserHandler(BaseHandler):
    
    def get(self):
        acto = session.get("access_token")
        if acto: return {"user": auth_lite_client.get_user_data(acto)}
        code = self.get_argument('code')
        try:
            user = auth_lite_client.get_user(code)
            session = self.session
            session["access_token"] = user['access_token']
            session["refresh_token"] = user['refresh_token']
            self.write({"user": user})
        except:
            raise tornado.web.HTTPError(400)

class UpdateUserHandler(BaseHandler):
    
    def get(self):
        try:
            session = self.session
            access_token = session.get("access_token")
            self.redirect(auth_lite_client.generate_edit_user_url(access_token, url ="http://127.0.0.1:3535/re-auth"))
        except:
            raise tornado.web.HTTPError(400)

class ReAuthHandler(BaseHandler):
    
    def get(self):
        code = self.get_argument('code')
        try:
            user = auth_lite_client.re_auth(code)
            session = self.session
            session["access_token"] = user['access_token']
            session["refresh_token"] = user['refresh_token']
            self.write({"user": user})
        except:
            self.redirect("http://127.0.0.1:3535/validate-token")

class ValidateAccessTokenHandler(BaseHandler):
    
    def get(self):
        token_validator = get_auth_(self)
        self.write(token_validator)

def revoketokens(handler):
    try:
        session = handler.session
        return auth_lite_client.revoke_token(AccessToken=session.get("access_token"), revoke_all_tokens=True)
    except:
        handler.redirect(auth_lite_client.generate_url())

def revokeAccesstokens(handler):
    try:
        session = handler.session
        return auth_lite_client.revoke_token(AccessToken=session.get("access_token"))
    except:
        handler.redirect(auth_lite_client.generate_url())

class InvalidateAllTokenHandler(BaseHandler):
    
    def get(self):
        r = revoketokens(self)
        self.write(r)

class InvalidateAccessTokenHandler(BaseHandler):
    
    def get(self):
        r = revokeAccesstokens(self)
        self.write(r)

def make_app():
    return tornado.web.Application([
        (r"/", RootHandler),
        (r"/user", GetUserHandler),
        (r"/user-update", UpdateUserHandler),
        (r"/re-auth", ReAuthHandler),
        (r"/validate-token", ValidateAccessTokenHandler),
        (r"/sign-out", InvalidateAllTokenHandler),
        (r"/semi-sign-out", InvalidateAccessTokenHandler),
    ])

if __name__ == "__main__":
    parse_command_line()
    
    app = make_app()
    
    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': 300,
        'session.auto': True
    }
    app.session = SessionMiddleware(app, session_opts)
    
    app.listen(options.port)
    tornado.ioloop.IOLoop.current().start()
