from fastapi import FastAPI, Depends, HTTPException, status, Response, Request
from trustauthx.authlite import AuthLiteClient
from starlette.middleware.sessions import SessionMiddleware
import uvicorn
from starlette.responses import JSONResponse
from fastapi.responses import RedirectResponse

app = FastAPI()

app.add_middleware(SessionMiddleware, secret_key="your_secret_key")

auth_lite_client = AuthLiteClient(api_key="3d2db83f7ea843d69f397e12c4caaebeSKMAKFNUOROXDAUOTNJY", 
                        secret_key="efbefb11c273d6915fe9dda4541b9f05ee2d07e2a98bbb2b4efb0840303696db", 
                        org_id="2ecfd99a54454ccbb84c22c1700969d4dae6a71050e611ee88069dc8f7663e88")

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
    acto = request.session.get("access_token")
    if acto: return {"user": client.get_user_data(acto)}
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
def get_user(code:str,ac:bool, request: Request, client: AuthLiteClient = Depends(auth_client)):
    try:
        if ac:
            user = client.re_auth(code)
            request.session["access_token"] = user['access_token']
            request.session["refresh_token"] = user['refresh_token']
            return {"user": user}
        else: return "no changes made by user"
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