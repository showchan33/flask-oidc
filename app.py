from flask import Flask, g, request, Response, redirect, session, abort
from urllib.parse import urlencode, urlparse, parse_qs
from dotenv import load_dotenv
from functools import wraps
import os
import requests
import json
import base64
from datetime import datetime, timezone

from oidc_config import OidcConfig
import utils


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.config["SESSION_COOKIE_NAME"] = os.getenv("COOKIE_NAME")
# app.debug = True

if os.getenv("PROTOCOL") == "http":
  os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'


def require_auth(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    try:
      auth_check_inner()
    except StopIteration as e:
      abort(401, e)
    except Exception as e:
      abort(401, e)
    return f(*args, **kwargs)
  return decorated


@app.before_request
def before_request():
  g.config = OidcConfig()


@app.route('/')
def root():
  return "Welcome to the top page!"


@app.route('/login')
def login():

  # Create request for authorization
  authz_url, authz_headers, authz_body = \
    g.config.oauth.prepare_authorization_request(
      g.config.authorization_url,
      redirect_url=g.config.redirect_url,
      scope=g.config.scope,
        )

  auth_redirect_url = utils.get_auth_redirect_url(g.config.auth_redirect_param)

  if auth_redirect_url:
    session["rd"] = auth_redirect_url

  return redirect(authz_url)


@app.route('/callback')
def callback():

  try:
    _ = utils.get_payload_from_cookie(session)
  except StopIteration:
    url_parsed = urlparse(request.url)
    qs_d = parse_qs(url_parsed.query)
    state = qs_d['state'][0]

    token_url, token_headers, token_body = \
        g.config.oauth.prepare_token_request(
            g.config.token_url,
            authorization_response=request.url,
            client_secret=g.config.client_secret,
            redirect_url=g.config.redirect_url,
            state=state,
        )

    token_res = None
    try:
      # Retrieve an access token
      token_res = requests.post(
        token_url, data=token_body, headers=token_headers
      )
      token_res.raise_for_status()
    except requests.exceptions.HTTPError:
      abort(500, 'Failed to get token response.')

    token_res_json = json.loads(token_res.content.decode('utf-8'))

    id_token = None

    try:
      id_token = token_res_json['id_token'].split(".")
    except KeyError:
      abort(500, 'Failed to get id token.')

    # Padding with “=” to avoid errors if the number of characters is not a multiple of 4
    id_token[1] = id_token[1] + '=' * (-len(id_token[1]) % 4)

    payload = base64.urlsafe_b64decode(id_token[1]).decode('utf-8')
    session_key = utils.generate_key_of_session()

    session[session_key] = payload

  auth_redirect_url_default = f"{g.config.server_url}/show-payload"
  auth_redirect_url_from_session = session.pop("rd", None)

  if auth_redirect_url_from_session is not None:
    auth_redirect_url = auth_redirect_url_from_session
  else:
    auth_redirect_url = auth_redirect_url_default

  return redirect(auth_redirect_url)


@app.route("/logout")
def logout():
  session.clear()
  params = {
      "returnTo": g.config.server_url,
      "client_id": g.config.client_id,
  }
  return redirect(f"{g.config.logout_url}?{urlencode(params)}")


@app.route("/show-payload")
@require_auth
def show_payload():
  try:
    _first_key, payload_string = utils.get_payload_from_cookie(session)
    payload = json.loads(payload_string)
    return Response(
      json.dumps(payload, indent=2),
      content_type='application/json; charset=utf-8'
    )
  except StopIteration:
    abort(500, "Failed to get payload")


@app.route("/secret")
@require_auth
def secret():
  return 'This page is only accessible to authenticated users.'


@app.route('/auth-check')
def auth_check():
  try:
    auth_check_inner()
  except StopIteration as e:
    abort(401, e)
  except Exception as e:
    abort(401, e)

  return ''


def auth_check_inner():
  try:
    _first_key, payload_string = utils.get_payload_from_cookie(session)
  except StopIteration:
    raise StopIteration("Unauthorized")

  try:
    payload = json.loads(payload_string)
    exp_value = payload.get("exp")

    if exp_value is not None:
      exp = int(exp_value) if isinstance(exp_value, int) else None
      if exp is not None:
        now = int(datetime.now(timezone.utc).timestamp())
        if exp >= now:
          return "OK"
        else:
          raise Exception("Session expired.")
      else:
        raise Exception("Invalid expiry date value.")
    else:
      raise Exception("Invalid payload.")
  except KeyError:
    raise Exception("Unauthorized")
  except Exception as e:
    raise Exception(str(e))


if __name__ == "__main__":
  app.run(host='0.0.0.0', port=8080)
