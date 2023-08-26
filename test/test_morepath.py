import morepath
from authlite import AuthLiteClient
from webob.exc import HTTPException
from webob import Response, Request
from starlette.middleware.sessions import SessionMiddleware

class App(morepath.App):
    pass

App.commit()

app = App()

app.config.scan()

app.add_middleware(SessionMiddleware, secret_key="your_secret_key")

auth_lite_client = AuthLiteClient(api_key="f28ffe7f2e4a47d6a796b0c2df073aeeAVVQBFSSCXIQWNQIEPBI", 
                                  secret_key="8ad9741c8fd5a8f286fc34eba21e0871e63dff3dd67e3ea3a1b43077db9531f7", 
                                  org_id="c3621ed40ccc4fca955779fab8f776c921e8865e439211ee88069dc8f7663e88")

def auth_client(request):
    return auth_lite_client

def get_auth_(request):
    access_token = request.session.get("access_token")
    refresh_token = request.session.get("refresh_token")
    try:
        a = auth_client(request).validate_token_set(access_token=access_token, refresh_token=refresh_token)
        if not a.state:
            request.session["access_token"] = a.access
            request.session["refresh_token"] = a.refresh
            t = "Token Regenerated refresh Token Valid"
        else:
            t = "Access Token Valid"
        return t
    except Exception as e:
        # raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
        return Response.blank()

@App.path("/")
class Root(object):
    pass

@App.json(model=Root)
def get_root(request):
    return morepath.redirect(auth_client(request).generate_url())

@App.path("/user/{code}")
class User(object):
    def __init__(self, code):
        self.code = code

@App.json(model=User)
def get_user(self, request):
    try:
        user = auth_client(request).get_user(self.code)
        request.session["access_token"] = user['access_token']
        request.session["refresh_token"] = user['refresh_token']
        return {"user": user}
    except:
        raise HTTPException()

@App.path("/user-update")
class UserUpdate(object):
    pass

@App.json(model=UserUpdate)
def get_user_update(self, request):
    access_token = request.session.get("access_token")
    url = auth_client(request).generate_edit_user_url(access_token, url="http://127.0.0.1:3535/re-auth")
    return morepath.redirect(url)

@App.path("/re-auth/{code}")
class ReAuth(object):
    def __init__(self, code):
        self.code = code

@App.json(model=ReAuth)
def get_re_auth(self, request):
    try:
        user = auth_client(request).re_auth(self.code)
        request.session["access_token"] = user['access_token']
        request.session["refresh_token"] = user['refresh_token']
        return {"user": user}
    except:
        return morepath.redirect("http://127.0.0.1:3535/validate-token")

@App.json(model=Root, path="/validate-token")
def validate_access_token(self, request):
    return get_auth_(request)

@App.json(model=Root, path="/sign-out")
def invalidate_all_token(self, request):
    try:
        auth_client(request).revoke_token(AccessToken=request.session.get("access_token"), revoke_all_tokens=True)
        return "Tokens revoked"
    except:
        return morepath.redirect(auth_client(request).generate_url())

@App.json(model=Root, path="/semi-sign-out")
def invalidate_access_token(self, request):
    try:
        auth_client(request).revoke_token(AccessToken=request.session.get("access_token"))
        return "Access token revoked"
    except:
        return morepath.redirect(auth_client(request).generate_url())

if __name__ == '__main__':
    morepath.run(app, host='127.0.0.1', port=3535)
