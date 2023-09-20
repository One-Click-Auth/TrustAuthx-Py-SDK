from giotto import GiottoApp
from trustauthx.authlite import AuthLiteClient
from webob.exc import HTTPException
from webob import Response, Request
from starlette.middleware.sessions import SessionMiddleware

app = GiottoApp()

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

@app.route("/")
def root(request):
    return Response.redirect(auth_client(request).generate_url())

@app.route("/user")
def get_user(request, code):
    acto = request.session.get("access_token")
    if acto: return {"user": auth_lite_client.get_user_data(acto)}
    try:
        user = auth_client(request).get_user(code)
        request.session["access_token"] = user['access_token']
        request.session["refresh_token"] = user['refresh_token']
        return {"user": user}
    except:
        raise HTTPException()

@app.route("/user-update")
def get_user_update(request):
    access_token = request.session.get("access_token")
    url = auth_client(request).generate_edit_user_url(access_token, url="http://127.0.0.1:3535/re-auth")
    return Response.redirect(url)

@app.route("/re-auth")
def re_auth(request, code):
    try:
        user = auth_client(request).re_auth(code)
        request.session["access_token"] = user['access_token']
        request.session["refresh_token"] = user['refresh_token']
        return {"user": user}
    except:
        return Response.redirect("http://127.0.0.1:3535/validate-token")

@app.route("/validate-token")
async def validate_access_token(request):
    return get_auth_(request)

@app.route("/sign-out")
async def invalidate_all_token(request):
    try:
        auth_client(request).revoke_token(AccessToken=request.session.get("access_token"), revoke_all_tokens=True)
        return "Tokens revoked"
    except:
        return Response.redirect(auth_client(request).generate_url())

@app.route("/semi-sign-out")
async def invalidate_access_token(request):
    try:
        auth_client(request).revoke_token(AccessToken=request.session.get("access_token"))
        return "Access token revoked"
    except:
        return Response.redirect(auth_client(request).generate_url())

if __name__ == "__main__":
    from giotto.server import Server
    app_server = Server(app, port=3535)
    app_server.start()
