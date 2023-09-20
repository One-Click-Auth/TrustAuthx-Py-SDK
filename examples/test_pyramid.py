from pyramid.config import Configurator
from pyramid.response import Response
from pyramid.httpexceptions import HTTPFound, HTTPBadRequest
from pyramid.session import SignedCookieSessionFactory
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
        raise HTTPFound(auth_lite_client.generate_url())

def root(request):
    raise HTTPFound(auth_lite_client.generate_url())

def get_user(request):
    acto = request.session.get("access_token")
    if acto: return {"user": auth_lite_client.get_user_data(acto)}
    code = request.params.get('code')
    try:
        user = auth_lite_client.get_user(code)
        request.session["access_token"] = user['access_token']
        request.session["refresh_token"] = user['refresh_token']
        return Response(json.dumps({"user": user}))
    except:
        raise HTTPBadRequest()

def update_user(request):
    try:
        access_token = request.session.get("access_token")
        raise HTTPFound(auth_lite_client.generate_edit_user_url(access_token, url ="http://127.0.0.1:3535/re-auth"))
    except:
        raise HTTPBadRequest()

def re_auth(request):
    code = request.params.get('code')
    try:
        user = auth_lite_client.re_auth(code)
        request.session["access_token"] = user['access_token']
        request.session["refresh_token"] = user['refresh_token']
        return Response(json.dumps({"user": user}))
    except:
        raise HTTPFound("http://127.0.0.1:3535/validate-token")

def validate_access_token(request):
    token_validator = get_auth_(request)
    return Response(json.dumps(token_validator))

def revoketokens(request):
    try:
        return auth_lite_client.revoke_token(AccessToken=request.session.get("access_token"), revoke_all_tokens=True)
    except:
        raise HTTPFound(auth_lite_client.generate_url())

def revokeAccesstokens(request):
    try:
        return auth_lite_client.revoke_token(AccessToken=request.session.get("access_token"))
    except:
        raise HTTPFound(auth_lite_client.generate_url())

def invalidate_all_token(request):
    r = revoketokens(request)
    return r

def invalidate_access_token(request):
    r = revokeAccesstokens(request)
    return r

if __name__ == '__main__':
    with Configurator() as config:
        my_session_factory = SignedCookieSessionFactory('your_secret_key')
        config.set_session_factory(my_session_factory)
        
        config.add_route('root', '/')
        config.add_view(root, route_name='root')
        
        config.add_route('get_user', '/user')
        config.add_view(get_user, route_name='get_user')
        
        config.add_route('update_user', '/user-update')
        config.add_view(update_user, route_name='update_user')
        
        config.add_route('re_auth', '/re-auth')
        config.add_view(re_auth, route_name='re_auth')
        
        config.add_route('validate_access_token', '/validate-token')
        config.add_view(validate_access_token, route_name='validate_access_token')
        
        config.add_route('invalidate_all_token', '/sign-out')
        config.add_view(invalidate_all_token, route_name='invalidate_all_token')
        
        config.add_route('invalidate_access_token', '/semi-sign-out')
        config.add_view(invalidate_access_token, route_name='invalidate_access_token')
        
        app = config.make_wsgi_app()
