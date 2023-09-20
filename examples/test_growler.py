from growler import App
from trustauthx.authlite import AuthLiteClient
from starlette.middleware.sessions import SessionMiddleware
from growler.http import Response
from growler.middleware.sessions import SessionMiddleware

app = App()

app.use_middleware(SessionMiddleware, secret_key="your_secret_key")

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

@app.get("/")
async def root(request, response):
    return Response.redirect(auth_client(request).generate_url())

@app.get("/user")
async def get_user(request, response, code):
    acto = request.session.get("access_token")
    if acto: return {"user": auth_lite_client.get_user_data(acto)}
    try:
        user = auth_client(request).get_user(code)
        request.session["access_token"] = user['access_token']
        request.session["refresh_token"] = user['refresh_token']
        return {"user": user}
    except:
        raise HTTPException()

@app.get("/user-update")
async def get_user_update(request, response):
    access_token = request.session.get("access_token")
    url = auth_client(request).generate_edit_user_url(access_token, url="http://127.0.0.1:3535/re-auth")
    return Response.redirect(url)

@app.get("/re-auth")
async def re_auth(request, response, code):
    try:
        user = auth_client(request).re_auth(code)
        request.session["access_token"] = user['access_token']
        request.session["refresh_token"] = user['refresh_token']
        return {"user": user}
    except:
        return Response.redirect("http://127.0.0.1:3535/validate-token")

@app.get("/validate-token")
async def validate_access_token(request, response):
    return get_auth_(request)

@app.get("/sign-out")
async def invalidate_all_token(request, response):
    try:
        auth_client(request).revoke_token(AccessToken=request.session.get("access_token"), revoke_all_tokens=True)
        return "Tokens revoked"
    except:
        return Response.redirect(auth_client(request).generate_url())

@app.get("/semi-sign-out")
async def invalidate_access_token(request, response):
    try:
        auth_client(request).revoke_token(AccessToken=request.session.get("access_token"))
        return "Access token revoked"
    except:
        return Response.redirect(auth_client(request).generate_url())

app.create_server(host='127.0.0.1', port=3535)
