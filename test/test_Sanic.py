from sanic import Sanic, response
from sanic_session import Session, InMemorySessionInterface
from authlite import AuthLiteClient

app = Sanic(__name__)
Session(app, interface=InMemorySessionInterface())

auth_lite_client = AuthLiteClient(api_key="f28ffe7f2e4a47d6a796b0c2df073aeeAVVQBFSSCXIQWNQIEPBI", 
                        secret_key="8ad9741c8fd5a8f286fc34eba21e0871e63dff3dd67e3ea3a1b43077db9531f7", 
                        org_id="c3621ed40ccc4fca955779fab8f776c921e8865e439211ee88069dc8f7663e88")

async def get_auth_(request):
    session = request.ctx.session
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
        return response.redirect(auth_lite_client.generate_url())

@app.route("/")
async def root(request):
    return response.redirect(auth_lite_client.generate_url())

@app.route("/user")
async def get_user(request):
    code = request.args.get('code')
    try:
        user = auth_lite_client.get_user(code)
        session = request.ctx.session
        session["access_token"] = user['access_token']
        session["refresh_token"] = user['refresh_token']
        return response.json({"user": user})
    except:
        return response.json({"error": "Bad Request"}, status=400)

@app.route("/user-update")
async def update_user(request):
    try:
        session = request.ctx.session
        access_token = session.get("access_token")
        return response.redirect(auth_lite_client.generate_edit_user_url(access_token, url ="http://127.0.0.1:3535/re-auth"))
    except:
        return response.json({"error": "Bad Request"}, status=400)

@app.route("/re-auth")
async def re_auth(request):
    code = request.args.get('code')
    try:
        user = auth_lite_client.re_auth(code)
        session = request.ctx.session
        session["access_token"] = user['access_token']
        session["refresh_token"] = user['refresh_token']
        return response.json({"user": user})
    except:
        return response.redirect("http://127.0.0.1:3535/validate-token")

@app.route("/validate-token")
async def validate_access_token(request):
    token_validator = await get_auth_(request)
    return response.json(token_validator)

async def revoketokens(request):
    try:
        session = request.ctx.session
        return auth_lite_client.revoke_token(AccessToken=session.get("access_token"), revoke_all_tokens=True)
    except:
        return response.redirect(auth_lite_client.generate_url())

async def revokeAccesstokens(request):
    try:
        session = request.ctx.session
        return auth_lite_client.revoke_token(AccessToken=session.get("access_token"))
    except:
        return response.redirect(auth_lite_client.generate_url())

@app.route("/sign-out")
async def invalidate_all_token(request):
    r = await revoketokens(request)
    return r

@app.route("/semi-sign-out")
async def invalidate_access_token(request):
    r = await revokeAccesstokens(request)
    return r

if __name__ == "__main__":
    app.run(port=3535)
