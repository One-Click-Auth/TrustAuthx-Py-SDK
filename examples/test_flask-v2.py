from flask import Flask, request, redirect, session
from trustauthx.authlite import AuthLiteClient
import os

app = Flask(__name__)
app.secret_key = "your_secret_key"

auth_lite_client = AuthLiteClient(
                                  api_key=os.getenv('API_KEY'), 
                                  secret_key=os.getenv('API_SECRET'), 
                                  org_id=os.getenv('ORG_ID')
                                 )

def get_auth_status():
    access_token = session.get("access_token")
    refresh_token = session.get("refresh_token")
    try:
        a = auth_lite_client.validate_token_set(access_token=access_token, refresh_token=refresh_token)
        if not a.state:
            session["access_token"] = a.access
            session["refresh_token"] = a.refresh
            t = "Token Regenerated, refresh Token Valid" 
        else:
            t = "Access Token Valid"
        return t
    except Exception as e:
        return redirect(auth_lite_client.generate_url())

@app.route("/")
def root():
    return redirect(auth_lite_client.generate_url())

@app.route("/user")
def get_user():
    code = request.args.get('code')
    try:
        user = auth_lite_client.get_user(code)
        session["access_token"] = user['access_token']
        session["refresh_token"] = user['refresh_token']
        return {"user": user}
    except:
        return {"error": "Bad Request"}, 400

@app.route("/user-update")
def update_user():
    try:
        access_token = session.get("access_token")
        return redirect(auth_lite_client.generate_edit_user_url(access_token, url="http://127.0.0.1:3535/re-auth"))
    except:
        return {"error": "Bad Request"}, 400

@app.route("/re-auth")
def re_auth():
    code = request.args.get('code')
    try:
        user = auth_lite_client.re_auth(code)
        session["access_token"] = user['access_token']
        session["refresh_token"] = user['refresh_token']
        return {"user": user}
    except:
        return redirect("http://127.0.0.1:3535/validate-token")

@app.route("/validate-token")
def validate_access_token():
    token_validator = get_auth_status()
    return token_validator

def revoke_tokens():
    try:
        return auth_lite_client.revoke_token(AccessToken=session.get("access_token"), revoke_all_tokens=True)
    except:
        return redirect(auth_lite_client.generate_url())

def revoke_access_token():
    try:
        return auth_lite_client.revoke_token(AccessToken=session.get("access_token"))
    except:
        return redirect(auth_lite_client.generate_url())

@app.route("/sign-out")
def invalidate_all_tokens():
    r = revoke_tokens()
    return redirect("http://127.0.0.1:3535/validate-token")

@app.route("/semi-sign-out")
def invalidate_access_token():
    r = revoke_access_token()
    return "Revoked access token"

if __name__ == "__main__":
    app.run(port=3535)
