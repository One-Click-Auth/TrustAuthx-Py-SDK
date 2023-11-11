It is the official Python SDK for TrustAuthx. 

# TrustAuthX Python Connector SDK 🐍

TrustAuthX is a revolutionary AI-powered authentication platform that provides secure and seamless login experiences for your users. TrustAuthX uses a unique neuroform technology that analyzes the biometric and behavioral patterns of your users and verifies their identity in real time.

With TrustAuthX Python Connector SDK, you can easily integrate TrustAuthX authentication into your Python web applications. This SDK contains two components:

- **AuthLite**: A lightweight and simple interface that allows you to use TrustAuthX as a standalone authentication service. AuthLite handles the communication between your app and TrustAuthX servers, and provides you with a user-friendly UI for login and registration.
- **Standard**: A powerful and flexible interface that allows you to use TrustAuthX as a complementary authentication layer on top of your existing authentication system. Standard gives you full control over the customization and configuration of TrustAuthX authentication, and supports more than 20 popular Python web frameworks.

## Getting Started 🚀

To use TrustAuthX Python Connector SDK, you need to have a TrustAuthX account and credentials. You can create them for free on the [TrustAuthX app website].

Once you have your credentials, you can install the SDK using pip:

```bash
pip install trustauthx
```

You got it. I will add the following section under the Quick Start heading:

## Quick Start With AI 🚀

If you want to experience the magic of TrustAuthX neuroform technology, you can use our CLI command to create a fully functional web app with TrustAuthX authentication in seconds. Just run:

```bash
trustauthx neuroform <framework>
```

where `<framework>` is the name of your preferred Python web framework. For example, if you want to use Flask, you can run:

```bash
trustauthx neuroform flask
```

This will generate a Flask app with TrustAuthX authentication already integrated. You can then run the app and test it out. TrustAuthX neuroform will automatically analyze your framework and implement the best practices for TrustAuthX authentication. You don't need to write any code or configure any settings. TrustAuthX neuroform does it all for you. It's like having an AI assistant that builds your authentication system for you. How cool is that? 😎

For more details on how to use the neuroform CLI command, please refer to the [TrustAuthX documentation].


## Quick Start With Advance Usage & Customizations.

Then, you can import the SDK in your Python code:

```python
import trustauthx
```

Depending on your use case, you can choose to use either AuthLite or Standard interface. For more details on how to use them, please refer to the [TrustAuthX documentation].

## Examples 📝

Here are some examples of how to use TrustAuthX Python Connector SDK with different web frameworks:

- Flask

```python
from flask import Flask, request, redirect, session
from trustauthx.authlite import AuthLiteClient


app = Flask(__name__)
app.secret_key = "your_secret_key"

auth_lite_client = AuthLiteClient(api_key="f28ffe7f2e4a47d6a796b0c2df073aeeAVVQBFSSCXIQWNQIEPBI", 
                        secret_key="8ad9741c8fd5a8f286fc34eba21e0871e63dff3dd67e3ea3a1b43077db9531f7", 
                        org_id="c3621ed40ccc4fca955779fab8f776c921e8865e439211ee88069dc8f7663e88")

def get_auth_():
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
        return redirect(auth_lite_client.generate_edit_user_url(access_token, url ="http://127.0.0.1:3535/re-auth"))
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
    token_validator = get_auth_()
    return token_validator

def revoketokens():
    try:
        return auth_lite_client.revoke_token(AccessToken=session.get("access_token"), revoke_all_tokens=True)
    except:
        return redirect(auth_lite_client.generate_url())

def revokeAccesstokens():
    try:
        return auth_lite_client.revoke_token(AccessToken=session.get("access_token"))
    except:
        return redirect(auth_lite_client.generate_url())

@app.route("/sign-out")
def invalidate_all_token():
    r = revoketokens()
    return redirect("http://127.0.0.1:3535/validate-token")

@app.route("/semi-sign-out")
def invalidate_access_token():
    r = revokeAccesstokens()
    return "revoked access token"

if __name__ == "__main__":
    app.run(port=3535)

```

- Django

```python
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponseBadRequest
from django.contrib.sessions.backends.db import SessionStore
from trustauthx.authlite import AuthLiteClient

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
        return redirect(auth_lite_client.generate_url())

def root(request):
    return redirect(auth_lite_client.generate_url())

def get_user(request):
    code = request.GET.get('code')
    try:
        user = auth_lite_client.get_user(code)
        request.session["access_token"] = user['access_token']
        request.session["refresh_token"] = user['refresh_token']
        return JsonResponse({"user": user})
    except:
        return HttpResponseBadRequest()

def update_user(request):
    try:
        access_token = request.session.get("access_token")
        return redirect(auth_lite_client.generate_edit_user_url(access_token, url ="http://127.0.0.1:3535/re-auth"))
    except:
        return HttpResponseBadRequest()

def re_auth(request):
    code = request.GET.get('code')
    try:
        user = auth_lite_client.re_auth(code)
        request.session["access_token"] = user['access_token']
        request.session["refresh_token"] = user['refresh_token']
        return JsonResponse({"user": user})
    except:
        return redirect("http://127.0.0.1:3535/validate-token")

def validate_access_token(request):
    token_validator = get_auth_(request)
    return JsonResponse(token_validator)

def revoketokens(request):
    try:
        return auth_lite_client.revoke_token(AccessToken=request.session.get("access_token"), revoke_all_tokens=True)
    except:
        return redirect(auth_lite_client.generate_url())

def revokeAccesstokens(request):
    try:
        return auth_lite_client.revoke_token(AccessToken=request.session.get("access_token"))
    except:
        return redirect(auth_lite_client.generate_url())

def invalidate_all_token(request):
    r = revoketokens(request)
    return r

def invalidate_access_token(request):
    r = revokeAccesstokens(request)
    return r
```

For more examples and tutorials, please visit the [TrustAuthX documentation].

## Support 💬

If you have any questions, feedback, or issues, please feel free to contact us at support@trustauthx.com. We are always happy to hear from you and help you with your integration.

## License 📄

TrustAuthX Python Connector SDK is licensed under the MIT License. See the [LICENSE] file for more details.
