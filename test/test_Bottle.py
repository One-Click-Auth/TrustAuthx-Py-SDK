from bottle import Bottle, request, response, redirect
from beaker.middleware import SessionMiddleware
from authlite import AuthLiteClient

app = Bottle()

session_opts = {
    'session.type': 'memory',
    'session.cookie_expires': 300,
    'session.auto': True
}
app = SessionMiddleware(app, session_opts)

auth_lite_client = AuthLiteClient(api_key="f28ffe7f2e4a47d6a796b0c2df073aeeAVVQBFSSCXIQWNQIEPBI", 
                        secret_key="8ad9741c8fd5a8f286fc34eba21e0871e63dff3dd67e3ea3a1b43077db9531f7", 
                        org_id="c3621ed40ccc4fca955779fab8f776c921e8865e439211ee88069dc8f7663e88")

def get_auth_():
    session = request.environ['beaker.session']
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
        return redirect(auth_lite_client.generate_url())

@app.route("/")
def root():
    return redirect(auth_lite_client.generate_url())

@app.route("/user")
def get_user():
    code = request.query.code
    try:
        user = auth_lite_client.get_user(code)
        session = request.environ['beaker.session']
        session["access_token"] = user['access_token']
        session["refresh_token"] = user['refresh_token']
        return {"user": user}
    except:
        response.status = 400
        return {"error": "Bad Request"}

@app.route("/user-update")
def update_user():
    try:
        session = request.environ['beaker.session']
        access_token = session.get("access_token")
        return redirect(auth_lite_client.generate_edit_user_url(access_token, url ="http://127.0.0.1:3535/re-auth"))
    except:
        response.status = 400
        return {"error": "Bad Request"}

@app.route("/re-auth")
def re_auth():
    code = request.query.code
    try:
        user = auth_lite_client.re_auth(code)
        session = request.environ['beaker.session']
        session["access_token"] = user['access_token']
        session["refresh_token"] = user['refresh_token']
        return {"user": user}
    except:
        return redirect("http://127.0.0.1:3535/validate-token")

@app.route("/validate-token")
def validate_access_token():
    token_validator = get_auth_()
    return token_validator

def revoketokens():
    try:
        session = request.environ['beaker.session']
        return auth_lite_client.revoke_token(AccessToken=session.get("access_token"), revoke_all_tokens=True)
    except:
        return redirect(auth_lite_client.generate_url())

def revokeAccesstokens():
    try:
        session = request.environ['beaker.session']
        return auth_lite_client.revoke_token(AccessToken=session.get("access_token"))
    except:
        return redirect(auth_lite_client.generate_url())

@app.route("/sign-out")
def invalidate_all_token():
    r = revoketokens()
    return r

@app.route("/semi-sign-out")
def invalidate_access_token():
    r = revokeAccesstokens()
    return r

if __name__ == "__main__":
    from bottle import run
    run(app=app, port=3535)
