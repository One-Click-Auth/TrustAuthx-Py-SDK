import grok
from authlite import AuthLiteClient
from webob.exc import HTTPException
from webob import Response, Request
from starlette.middleware.sessions import SessionMiddleware

class Root(grok.View):
    pass

class User(grok.View):
    grok.require('zope.Public')

class UserUpdate(grok.View):
    grok.require('zope.Public')

class ReAuth(grok.View):
    grok.require('zope.Public')

class ValidateToken(grok.View):
    grok.require('zope.Public')

class SignOut(grok.View):
    grok.require('zope.Public')

class SemiSignOut(grok.View):
    grok.require('zope.Public')

app = grok.Application()

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
        return Response.redirect(client.generate_url())

if __name__ == "__main__":
    grok.global_utility(auth_client, provides=IAuthClient)
    grok.global_utility(get_auth_, provides=IGetAuthFunction)
    grok.global_utility(SessionMiddleware, secret_key="your_secret_key")

    app.run(port=3535)
