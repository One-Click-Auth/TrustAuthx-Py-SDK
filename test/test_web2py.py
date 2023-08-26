import web
from web import form
from beaker.middleware import SessionMiddleware
from authlite import AuthLiteClient

urls = (
    '/', 'root',
    '/user', 'get_user',
    '/user-update', 'update_user',
    '/re-auth', 're_auth',
    '/validate-token', 'validate_access_token',
    '/sign-out', 'invalidate_all_token',
    '/semi-sign-out', 'invalidate_access_token'
)

app = web.application(urls, globals())

session_opts = {
    'session.type': 'memory',
    'session.cookie_expires': 300,
    'session.auto': True
}
app.add_processor(web.loadhook(lambda: web.ctx.session))
app.add_processor(web.unloadhook(lambda: web.ctx.session.save()))
app = SessionMiddleware(app.wsgifunc(), session_opts)

auth_lite_client = AuthLiteClient(api_key="f28ffe7f2e4a47d6a796b0c2df073aeeAVVQBFSSCXIQWNQIEPBI", 
                        secret_key="8ad9741c8fd5a8f286fc34eba21e0871e63dff3dd67e3ea3a1b43077db9531f7", 
                        org_id="c3621ed40ccc4fca955779fab8f776c921e8865e439211ee88069dc8f7663e88")

def get_auth_():
    session = web.ctx.session
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
        return web.seeother(auth_lite_client.generate_url())

class root:
    
    def GET(self):
        return web.seeother(auth_lite_client.generate_url())

class get_user:
    
    def GET(self):
        code = web.input().code
        try:
            user = auth_lite_client.get_user(code)
            session = web.ctx.session
            session["access_token"] = user['access_token']
            session["refresh_token"] = user['refresh_token']
            return {"user": user}
        except:
            return web.HTTPError('400 Bad Request')

class update_user:
    
    def GET(self):
        try:
            session = web.ctx.session
            access_token = session.get("access_token")
            return web.seeother(auth_lite_client.generate_edit_user_url(access_token, url ="http://127.0.0.1:3535/re-auth"))
        except:
            return web.HTTPError('400 Bad Request')

class re_auth:
    
    def GET(self):
        code = web.input().code
        try:
            user = auth_lite_client.re_auth(code)
            session = web.ctx.session
            session["access_token"] = user['access_token']
            session["refresh_token"] = user['refresh_token']
            return {"user": user}
        except:
            return web.seeother("http://127.0.0.1:3535/validate-token")

class validate_access_token:
    
    def GET(self):
        token_validator = get_auth_()
        return token_validator

def revoketokens():
    try:
        session = web.ctx.session
        return auth_lite_client.revoke_token(AccessToken=session.get("access_token"), revoke_all_tokens=True)
    except:
        return web.seeother(auth_lite_client.generate_url())

def revokeAccesstokens():
    try:
        session = web.ctx.session
        return auth_lite_client.revoke_token(AccessToken=session.get("access_token"))
    except:
        return web.seeother(auth_lite_client.generate_url())

class invalidate_all_token:
    
    def GET(self):
        r = revoketokens()
        return r

class invalidate_access_token:
    
    def GET(self):
        r = revokeAccesstokens()
        return r

if __name__ == "__main__":
    app.run()
