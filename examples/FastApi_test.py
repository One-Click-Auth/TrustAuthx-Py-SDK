from fastapi import FastAPI, Depends, HTTPException, status, Response, Request
from trustauthx.authlite import AuthLiteClient
from starlette.middleware.sessions import SessionMiddleware
import uvicorn
from starlette.responses import JSONResponse
from fastapi.responses import RedirectResponse

app = FastAPI()

app.add_middleware(SessionMiddleware, secret_key="your_secret_key")

auth_lite_client = AuthLiteClient(api_key="f28ffe7f2e4a47d6a796b0c2df073aeeAVVQBFSSCXIQWNQIEPBI", 
                        secret_key="8ad9741c8fd5a8f286fc34eba21e0871e63dff3dd67e3ea3a1b43077db9531f7", 
                        org_id="c3621ed40ccc4fca955779fab8f776c921e8865e439211ee88069dc8f7663e88")

async def auth_client():return auth_lite_client

def get_auth_(request: Request, client: AuthLiteClient=Depends(auth_client)):
        access_token = request.session.get("access_token")
        refresh_token = request.session.get("refresh_token")
        try:
            a = client.validate_token_set(access_token=access_token, refresh_token=refresh_token)
            if not a.state:
                request.session["access_token"] = a.access
                request.session["refresh_token"] = a.refresh
                t="Token Regenerated refresh Token Valid" 
            else:t="Access Token Valid"
            return t
        except Exception as e:
            # raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
            return RedirectResponse(client.generate_url())

@app.get("/")
def root(client: AuthLiteClient = Depends(auth_client)):return RedirectResponse(client.generate_url())

@app.get("/user")
def get_user(code: str, request: Request, client: AuthLiteClient = Depends(auth_client)):
    try:
        user = client.get_user(code)
        request.session["access_token"] = user['access_token']
        request.session["refresh_token"] = user['refresh_token']
        return {"user": user}
    except:raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

@app.get("/user-update")
def get_user(request: Request, client: AuthLiteClient = Depends(auth_client)):
    try:
        access_token = request.session.get("access_token")
        return RedirectResponse(client.generate_edit_user_url(access_token, url ="http://127.0.0.1:3535/re-auth"))
    except:raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

@app.get("/re-auth")
def get_user(code:str, request: Request, client: AuthLiteClient = Depends(auth_client)):
    try:
        user = client.re_auth(code)
        request.session["access_token"] = user['access_token']
        request.session["refresh_token"] = user['refresh_token']
        return {"user": user}
    except:return RedirectResponse("http://127.0.0.1:3535/validate-token")

@app.get("/validate-token")
async def validate_access_token(token_validator: AuthLiteClient=Depends(get_auth_)):return token_validator

async def revoketokens(request: Request, client: AuthLiteClient=Depends(auth_client)):
    try:return client.revoke_token(AccessToken=request.session.get("access_token"), revoke_all_tokens=True)
    except:
        # raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
        return RedirectResponse(client.generate_url())

async def revokeAccesstokens(request: Request, client: AuthLiteClient=Depends(auth_client)):
    try:return client.revoke_token(AccessToken=request.session.get("access_token"))
    except:
        # raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
        return RedirectResponse(client.generate_url())

@app.get("/sign-out")
async def invalidate_all_token(r = Depends(revoketokens)):return r

@app.get("/semi-sign-out")
async def invalidate_access_token(r = Depends(revokeAccesstokens)):return r

uvicorn.run(app=app, port = 3535)