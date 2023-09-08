import falcon
from falcon import Request, Response
from trustauthx.authlite import AuthLiteClient

class AuthMiddleware(object):
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
    
    def process_request(self, req: Request, resp: Response):
        req.context['session'] = req.cookies.get('session')
    
    def process_response(self, req: Request, resp: Response, resource, req_succeeded: bool):
        if 'session' in req.context:
            resp.set_cookie('session', req.context['session'], max_age=3600)

auth_lite_client = AuthLiteClient(api_key="f28ffe7f2e4a47d6a796b0c2df073aeeAVVQBFSSCXIQWNQIEPBI", 
                        secret_key="8ad9741c8fd5a8f286fc34eba21e0871e63dff3dd67e3ea3a1b43077db9531f7", 
                        org_id="c3621ed40ccc4fca955779fab8f776c921e8865e439211ee88069dc8f7663e88")

def get_auth_(req: Request):
    access_token = req.context['session'].get("access_token")
    refresh_token = req.context['session'].get("refresh_token")
    try:
        a = auth_lite_client.validate_token_set(access_token=access_token, refresh_token=refresh_token)
        if not a.state:
            req.context['session']["access_token"] = a.access
            req.context['session']["refresh_token"] = a.refresh
            t="Token Regenerated refresh Token Valid" 
        else:t="Access Token Valid"
        return t
    except Exception as e:
        raise falcon.HTTPFound(auth_lite_client.generate_url())

class RootResource(object):
    
    def on_get(self, req: Request, resp: Response):
        raise falcon.HTTPFound(auth_lite_client.generate_url())

class UserResource(object):
    
    def on_get(self, req: Request, resp: Response):
        code = req.get_param('code')
        try:
            user = auth_lite_client.get_user(code)
            req.context['session']["access_token"] = user['access_token']
            req.context['session']["refresh_token"] = user['refresh_token']
            resp.media = {"user": user}
        except:
            raise falcon.HTTPBadRequest()

class UpdateUserResource(object):
    
    def on_get(self, req: Request, resp: Response):
        try:
            access_token = req.context['session'].get("access_token")
            raise falcon.HTTPFound(auth_lite_client.generate_edit_user_url(access_token, url ="http://127.0.0.1:3535/re-auth"))
        except:
            raise falcon.HTTPBadRequest()

class ReAuthResource(object):
    
    def on_get(self, req: Request, resp: Response):
        code = req.get_param('code')
        try:
            user = auth_lite_client.re_auth(code)
            req.context['session']["access_token"] = user['access_token']
            req.context['session']["refresh_token"] = user['refresh_token']
            resp.media = {"user": user}
        except:
            raise falcon.HTTPFound("http://127.0.0.1:3535/validate-token")

class ValidateTokenResource(object):
    
    def on_get(self, req: Request, resp: Response):
        token_validator = get_auth_(req)
        resp.media = token_validator

def revoketokens(req: Request):
    try:
        return auth_lite_client.revoke_token(AccessToken=req.context['session'].get("access_token"), revoke_all_tokens=True)
    except:
        raise falcon.HTTPFound(auth_lite_client.generate_url())

def revokeAccesstokens(req: Request):
    try:
        return auth_lite_client.revoke_token(AccessToken=req.context['session'].get("access_token"))
    except:
        raise falcon.HTTPFound(auth_lite_client.generate_url())

class InvalidateAllTokenResource(object):
    
    def on_get(self, req: Request, resp: Response):
        r = revoketokens(req)
        resp.media = r

class InvalidateAccessTokenResource(object):
    
    def on_get(self, req: Request, resp: Response):
        r = revokeAccesstokens(req)
        resp.media = r

app = falcon.API(middleware=[AuthMiddleware(secret_key="your_secret_key")])
app.add_route('/', RootResource())
app.add_route('/user', UserResource())
app.add_route('/user-update', UpdateUserResource())
app.add_route('/re-auth', ReAuthResource())
app.add_route('/validate-token', ValidateTokenResource())
app.add_route('/sign-out', InvalidateAllTokenResource())
app.add_route('/semi-sign-out', InvalidateAccessTokenResource())
