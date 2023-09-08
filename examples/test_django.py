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