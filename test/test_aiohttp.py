from aiohttp import web
from aiohttp_session import setup, get_session, session_middleware
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from authlite import AuthLiteClient

app = web.Application()

setup(app, EncryptedCookieStorage(b'your_secret_key'))

auth_lite_client = AuthLiteClient(api_key="f28ffe7f2e4a47d6a796b0c2df073aeeAVVQBFSSCXIQWNQIEPBI", 
                        secret_key="8ad9741c8fd5a8f286fc34eba21e0871e63dff3dd67e3ea3a1b43077db9531f7", 
                        org_id="c3621ed40ccc4fca955779fab8f776c921e8865e439211ee88069dc8f7663e88")

async def get_auth_(request):
    session = await get_session(request)
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
        raise web.HTTPFound(auth_lite_client.generate_url())

async def root(request):
    raise web.HTTPFound(auth_lite_client.generate_url())

async def get_user(request):
    code = request.query.get('code')
    try:
        user = auth_lite_client.get_user(code)
        session = await get_session(request)
        session["access_token"] = user['access_token']
        session["refresh_token"] = user['refresh_token']
        return web.json_response({"user": user})
    except:
        raise web.HTTPBadRequest()

async def update_user(request):
    try:
        session = await get_session(request)
        access_token = session.get("access_token")
        raise web.HTTPFound(auth_lite_client.generate_edit_user_url(access_token, url ="http://127.0.0.1:3535/re-auth"))
    except:
        raise web.HTTPBadRequest()

async def re_auth(request):
    code = request.query.get('code')
    try:
        user = auth_lite_client.re_auth(code)
        session = await get_session(request)
        session["access_token"] = user['access_token']
        session["refresh_token"] = user['refresh_token']
        return web.json_response({"user": user})
    except:
        raise web.HTTPFound("http://127.0.0.1:3535/validate-token")

async def validate_access_token(request):
    token_validator = await get_auth_(request)
    return web.json_response(token_validator)

async def revoketokens(request):
    try:
        session = await get_session(request)
        return auth_lite_client.revoke_token(AccessToken=session.get("access_token"), revoke_all_tokens=True)
    except:
        raise web.HTTPFound(auth_lite_client.generate_url())

async def revokeAccesstokens(request):
    try:
        session = await get_session(request)
        return auth_lite_client.revoke_token(AccessToken=session.get("access_token"))
    except:
        raise web.HTTPFound(auth_lite_client.generate_url())

async def invalidate_all_token(request):
    r = await revoketokens(request)
    return r

async def invalidate_access_token(request):
    r = await revokeAccesstokens(request)
    return r

app.add_routes([web.get('/', root),
                web.get('/user', get_user),
                web.get('/user-update', update_user),
                web.get('/re-auth', re_auth),
                web.get('/validate-token', validate_access_token),
                web.get('/sign-out', invalidate_all_token),
                web.get('/semi-sign-out', invalidate_access_token)])

if __name__ == '__main__':
    web.run_app(app, port=3535)
