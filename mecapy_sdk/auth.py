"""Authentication module (Authorization Code + PKCE) for MecaPy SDK."""

import http.server
import json
import secrets
import socket
import urllib.parse
import webbrowser

import authlib
import keyring
import requests
from authlib.integrations.requests_client import OAuth2Session

from .config import config as conf



class OAuthCallbackHandler(http.server.BaseHTTPRequestHandler):
    """
    Handles OAuth callback HTTP GET requests.

    This class is a custom HTTP request handler designed to handle the callback
    in an OAuth authentication flow. It processes GET requests, retrieves the
    authorization code from the query parameters, and handles the response
    accordingly. If an authorization code is found, it stores the code in the
    server instance and sends a success response; otherwise, it sends an error
    response.

    Attributes
    ----------
    server : http.server.HTTPServer
        The HTTP server instance associated with this request handler. This
        attribute is used to store the authorization code when received.
    """

    def do_GET(self):
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        code = params.get("code")
        if code:
            self.server.auth_code = code[0]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<h1>Authentication successful!</h1><p>You can close this window.</p>")
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"<h1>Error: code not found</h1>")


class MecapySdkAuth:
    def __init__(self):
        self.client_id = conf.auth.client_id
        self.realm = conf.auth.realm
        self.issuer = conf.auth.issuer
        self.scopes = ["openid", "profile", "email"]

        self.port = self.set_port(8085, 8086, 8087, 8088, 8089)
        self.redirect_uri = f"http://localhost:{self.port}/callback"

        self.auth_code = None

        oidc_conf = self.fetch_oidc_config()
        self.authorization_endpoint = oidc_conf["authorization_endpoint"]
        self.token_endpoint = oidc_conf["token_endpoint"]

    def set_port(self, *ports):
        for port in ports:
            if self.is_port_free(port):
                return port
        raise Exception("No free port found")

    @staticmethod
    def is_port_free(port: int) -> bool:
        """Vérifie si un port est libre sur localhost."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            try:
                s.bind(("127.0.0.1", port))
                return True  # bind réussi → port libre
            except OSError:
                return False  # bind échoué → port occupé

    def fetch_oidc_config(self) -> dict[str, str]:
        """
        Fetch the OpenID Connect (OIDC) configuration for a given issuer.

        This function sends an HTTP GET request to retrieve the .well-known/openid-
        configuration document, which provides metadata necessary to interact with the
        OIDC service for the specified issuer. The response is returned in JSON format.

        Returns
        -------
        dict
            A dictionary containing the OIDC configuration details retrieved from the
            issuer.

        Raises
        ------
        requests.exceptions.RequestException
            Raised if there is an issue with the HTTP GET request or the response, such
            as a connection error, timeout, or invalid response status.
        """
        discovery_url = conf.auth.get_oidc_discovery_url()
        resp = requests.get(discovery_url)
        resp.raise_for_status()
        return resp.json()

    def waiting_for_code(self):
        # Démarrer serveur local
        with http.server.HTTPServer(("localhost", self.port), OAuthCallbackHandler) as server:
            server.handle_request()
            auth_code = getattr(server, "auth_code", None)
        if auth_code:
            return auth_code
        else:
            raise Exception("No code received from Keycloak")

    def login(self):
        client = OAuth2Session(client_id=self.client_id,
                               redirect_uri=self.redirect_uri,
                               token_endpoint=self.token_endpoint,
                               code_challenge_method="S256")
        print(f"client_id = {self.client_id}")
        print(f"redirect_uri = {self.redirect_uri}")
        code_verifier = secrets.token_urlsafe(48)

        # URL d’autorisation
        uri, state = client.create_authorization_url(self.authorization_endpoint, code_verifier=code_verifier)

        print("Opening browser for login:", uri)
        webbrowser.open(uri)

        # Attend le code via le mini serveur local
        auth_code = self.waiting_for_code()
        print(f"auth_code = {auth_code}")

        # Échange code contre token
        token = client.fetch_token(self.token_endpoint, code=auth_code, code_verifier=code_verifier)

        # Sauvegarde dans keyring
        keyring.set_password("MecaPy", "token", json.dumps(token))

        return token

    def logout(self):
        client = self.get_session()
        client.revoke_token(self.token_endpoint, token=client.token, token_type_hint="access_token")
        client.revoke_token(self.token_endpoint, token=client.token, token_type_hint="refresh_token")
        keyring.delete_password("MecaPy", "token")

    def get_token(self):
        token_as_str = keyring.get_password("MecaPy", "token")
        if token_as_str is None:
            return self.login()
        return json.loads(token_as_str)

    def get_session(self):
        token = self.get_token()
        session = OAuth2Session(client_id=self.client_id, token_endpoint=self.token_endpoint, token=token)
        try:
            session.ensure_active_token()
            return session
        except authlib.integrations.base_client.errors.OAuthError:
            token = self.login()
            return OAuth2Session(client_id=self.client_id, token_endpoint=self.token_endpoint, token=token)

    async def get_access_token(self) -> str:
        """
        Get access token for compatibility with existing client code.

        Returns
        -------
        str
            The access token string
        """
        token_data = self.get_token()
        access_token = token_data.get("access_token")
        if not access_token:
            raise Exception("No access token found in token response")
        return access_token

