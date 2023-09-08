import dash
from dash.dependencies import Input, Output, State
import dash_core_components as dcc
import dash_html_components as html
from flask import Flask, redirect, request
from flask_session import Session
from trustauthx.authlite import AuthLiteClient

server = Flask(__name__)
server.config['SECRET_KEY'] = 'your_secret_key'
server.config['SESSION_TYPE'] = 'filesystem'
Session(server)

app = dash.Dash(__name__, server=server)

auth_lite_client = AuthLiteClient(api_key="f28ffe7f2e4a47d6a796b0c2df073aeeAVVQBFSSCXIQWNQIEPBI", 
                        secret_key="8ad9741c8fd5a8f286fc34eba21e0871e63dff3dd67e3ea3a1b43077db9531f7", 
                        org_id="c3621ed40ccc4fca955779fab8f776c921e8865e439211ee88069dc8f7663e88")

def get_auth_():
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

app.layout = html.Div([
    dcc.Location(id='url', refresh=False),
    html.Div(id='page-content')
])

@app.callback(Output('page-content', 'children'),
              Input('url', 'pathname'))
def display_page(pathname):
    if pathname == '/':
        return redirect(auth_lite_client.generate_url())
    elif pathname == '/user':
        code = request.args.get('code')
        try:
            user = auth_lite_client.get_user(code)
            request.session["access_token"] = user['access_token']
            request.session["refresh_token"] = user['refresh_token']
            return html.Div([
                html.H1('User'),
                html.Pre(str(user))
            ])
        except:
            return html.Div([
                html.H1('Error'),
                html.Pre('Bad Request')
            ])
    elif pathname == '/user-update':
        try:
            access_token = request.session.get("access_token")
            return redirect(auth_lite_client.generate_edit_user_url(access_token, url ="http://127.0.0.1:3535/re-auth"))
        except:
            return html.Div([
                html.H1('Error'),
                html.Pre('Bad Request')
            ])
    elif pathname == '/re-auth':
        code = request.args.get('code')
        try:
            user = auth_lite_client.re_auth(code)
            request.session["access_token"] = user['access_token']
            request.session["refresh_token"] = user['refresh_token']
            return html.Div([
                html.H1('User'),
                html.Pre(str(user))
            ])
        except:
            return redirect("http://127.0.0.1:3535/validate-token")
    elif pathname == '/validate-token':
        token_validator = get_auth_()
        return html.Div([
            html.H1('Token Validator'),
            html.Pre(str(token_validator))
        ])
    elif pathname == '/sign-out':
        r = revoketokens()
        return r
    elif pathname == '/semi-sign-out':
        r = revokeAccesstokens()
        return r
    else:
        return '404'

def revoketokens():
    try:
        return auth_lite_client.revoke_token(AccessToken=request.session.get("access_token"), revoke_all_tokens=True)
    except:
        return redirect(auth_lite_client.generate_url())

def revokeAccesstokens():
    try:
        return auth_lite_client.revoke_token(AccessToken=request.session.get("access_token"))
    except:
        return redirect(auth_lite_client.generate_url())

if __name__ == '__main__':
    app.run_server(port=3535)
