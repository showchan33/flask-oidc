import random
from flask import request
from urllib.parse import unquote


def generate_key_of_session() -> str:
  hash = random.getrandbits(32)
  return format(hash, '08x')


def get_payload_from_cookie(session):
  key = next(k for k in session if k != "rd")
  payload = session[key]
  return key, payload


def get_auth_redirect_url(auth_redirect_param: str) -> str:
  if auth_redirect_param:
    redirect_uri = request.args.get(auth_redirect_param)
    if redirect_uri:
      return unquote(redirect_uri)
  return None
