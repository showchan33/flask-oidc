from dotenv import load_dotenv
import os
from oauthlib.oauth2 import WebApplicationClient

load_dotenv()


class OidcConfig:
  def __init__(self):
    self.authorization_url = os.getenv('OIDC_AUTHORIZATION_URL')
    self.token_url = os.getenv("OIDC_TOKEN_URL")
    self.logout_url = os.getenv("OIDC_LOGOUT_URL")
    self.scope = os.getenv("OIDC_SCOPES", "openid,email,profile")
    self.client_id = os.getenv("OIDC_CLIENT_ID")
    self.client_secret = os.getenv("OIDC_CLIENT_SECRET")

    self.server_url = os.getenv("SERVER_URL")
    self.redirect_url = f"{self.server_url}/callback"

    self.auth_redirect_param = os.getenv("AUTH_REDIRECT_PARAM")

    self.oauth = WebApplicationClient(self.client_id)
