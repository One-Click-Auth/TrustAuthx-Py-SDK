from starlette.applications import Starlette
from starlette.responses import JSONResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.routing import Route
from trustauthx.authlite import AuthLiteClient

app = Starlette()
app.add_middleware(SessionMiddleware, secret_key="your_secret_key")

auth_lite_client = AuthLiteClient(api_key="f28ffe7f2e4a47d6a796b0c2df073aeeAVVQBFSSCXIQWNQIEPBI", 
                        secret_key="8ad9741c8fd5a8f286fc34eba21e0871e63dff3dd67e3ea3a1b43077db9531f7", 
                        org_id="c3621ed40ccc4fca955779fab8f776c921e8865e439211ee88069dc8f7663e88")

def get_auth_(request):
    access_token = request.session.get("access_token")
    refresh_token = request.session.get("refresh_token")
    try:
        a = auth_lite_client.validate_token_set(access_token=access_token, refresh_token=refresh_token)
        if not a.state:
            request.session["access_token"] = a.access
            request.session["refresh_token"] = a.refresh
            t="Token Regenerated refresh Token Valid" 
        else:t="Access Token Valid"
        return t
    except Exception as e:
        return RedirectResponse(auth_lite_client.generate_url())

async def root(request):
    return RedirectResponse(auth_lite_client.generate_url())

async def get_user(request):
    acto = request.session.get("access_token")
    if acto: return {"user": auth_lite_client.get_user_data(acto)}
    code = request.query_params['code']
    try:
        user = auth_lite_client.get_user(code)
        request.session["access_token"] = user['access_token']
        request.session["refresh_token"] = user['refresh_token']
        return JSONResponse({"user": user})
    except:
        return JSONResponse({"error": "Bad Request"}, status_code=400)

async def update_user(request):
    try:
        access_token = request.session.get("access_token")
        return RedirectResponse(auth_lite_client.generate_edit_user_url(access_token, url ="http://127.0.0.1:3535/re-auth"))
    except:
        return JSONResponse({"error": "Bad Request"}, status_code=400)

async def re_auth(request):
    code = request.query_params['code']
    try:
        user = auth_lite_client.re_auth(code)
        request.session["access_token"] = user['access_token']
        request.session["refresh_token"] = user['refresh_token']
        return JSONResponse({"user": user})
    except:
        return RedirectResponse("http://127.0.0.1:3535/validate-token")

async def validate_access_token(request):
    token_validator = get_auth_(request)
    return JSONResponse(token_validator)

def revoketokens(request):
    try:
        return auth_lite_client.revoke_token(AccessToken=request.session.get("access_token"), revoke_all_tokens=True)
    except:
        return RedirectResponse(auth_lite_client.generate_url())

def revokeAccesstokens(request):
    try:
        return auth_lite_client.revoke_token(AccessToken=request.session.get("access_token"))
    except:
        return RedirectResponse(auth_lite_client.generate_url())

async def invalidate_all_token(request):
    r = revoketokens(request)
    return r

async def invalidate_access_token(request):
    r = revokeAccesstokens(request)
    return r

app.routes.extend([
    Route('/', root),
    Route('/user', get_user),
    Route('/user-update', update_user),
    Route('/re-auth', re_auth),
    Route('/validate-token', validate_access_token),
    Route('/sign-out', invalidate_all_token),
    Route('/semi-sign-out', invalidate_access_token),
])
