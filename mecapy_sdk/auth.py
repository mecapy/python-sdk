"""Authentication module (Authorization Code + PKCE) for MecaPy SDK."""

import base64
import hashlib
import http.server
import secrets
import socket
import urllib.parse
import webbrowser

import requests

# ----------------------------
# CONFIGURATION
# ----------------------------
ISSUER = "http://localhost:8080/realms/mecapy"  # ex: https://mykeycloak.example.com/realms/myrealm
CLIENT_ID = "mecapy-api-public"
SCOPES = ["openid", "profile", "email"]
CALLBACK_PATH = "/callback"


# ----------------------------
# Helper PKCE
# ----------------------------
def generate_pkce_pair() -> (str, str):
    """
    Generate a PKCE (Proof Key for Code Exchange) pair.

    This function creates and returns a `code_verifier` and a `code_challenge` pair, which
    are used in the PKCE flow for securely exchanging authorization codes in OAuth 2.0.
    The `code_verifier` is a high-entropy cryptographic random string. The `code_challenge`
    is derived by applying a SHA-256 hash to the `code_verifier` and encoding the result
    in Base64 URL encoding.

    Returns
    -------
    code_verifier (str):
        A cryptographically secure random string used in the PKCE flow.
    code_challenge (str):
        A hashed and encoded representation of the `code_verifier` suitable for secure
        authorization code exchange.
    """
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode("ascii")
    )
    return code_verifier, code_challenge


def get_free_port() -> int:
    """
    Get a free port on the machine.

    This function creates a temporary socket, binds it to a random port, and
    retrieves an available port number that can be used. It ensures that the port
    retrieved is not in use, freeing up the socket immediately afterward. This
    provides a reliable way to determine free ports dynamically.

    Returns
    -------
    int
        A randomly selected open port number available for use.

    """
    s = socket.socket()
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ----------------------------
# Découverte OIDC
# ----------------------------
def fetch_oidc_config(issuer: str) -> dict[str, str]:
    """
    Fetches the OpenID Connect (OIDC) configuration for a given issuer.

    This function sends an HTTP GET request to retrieve the .well-known/openid-
    configuration document, which provides metadata necessary to interact with the
    OIDC service for the specified issuer. The response is returned in JSON format.

    Parameters
    ----------
    issuer : str
        The base URL of the OpenID Connect issuer for which the OIDC configuration
        is being fetched.
        For keycloak, issuer is https://<keycloak-or-auth0-domain>/realms/<realm>

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
    resp = requests.get(f"{issuer}/.well-known/openid-configuration")
    resp.raise_for_status()
    return resp.json()


# ----------------------------
# Serveur local pour récupérer le code
# ----------------------------
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


# ----------------------------
# Fonction principale
# ----------------------------
def authenticate():
    """
    Authenticate a user using the OAuth 2.0 authorization code flow with PKCE.

    This function facilitates authentication by performing the following steps:
    1. Generates a code verifier and challenge pair using PKCE.
    2. Identifies an available port for setting up a local callback server.
    3. Discovers the OIDC endpoints by fetching the configuration from the issuer.
    4. Constructs the authorization URL and opens it in a browser to prompt user authentication.
    5. Starts a local HTTP server to intercept the authorization code.
    6. Exchanges the authorization code received via callback for tokens from the token endpoint.
    7. Returns the access and refresh tokens.

    Returns
    -------
    dict
        Dictionary containing the access and refresh tokens.

    Raises
    ------
    HTTPError
        If the token endpoint responds with an error during token exchange.

    Notes
    -----
    Generating a code verifier/challenge pair and running a local callback server enables
    the client to securely receive the authorization code in a controlled way.
    """
    # PKCE
    code_verifier, code_challenge = generate_pkce_pair()

    # Port libre pour callback
    port = get_free_port()
    port = 40429
    redirect_uri = f"http://localhost:{port}{CALLBACK_PATH}"
    print("Found port:", port)

    # Discovery OIDC
    config = fetch_oidc_config(ISSUER)
    authorization_endpoint = config["authorization_endpoint"]
    token_endpoint = config["token_endpoint"]

    # Construire URL auth
    auth_url = (
        authorization_endpoint
        + "?"
        + urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": CLIENT_ID,
                "redirect_uri": redirect_uri,
                "scope": " ".join(SCOPES),
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
    )

    # Démarrer serveur local
    with http.server.HTTPServer(("localhost", port), OAuthCallbackHandler) as server:
        print(f"Opening browser for authentication, listening on {redirect_uri}...")
        webbrowser.open(auth_url)

        # Attendre le code
        server.handle_request()
        auth_code = server.auth_code

    # Echanger code contre token
    token_resp = requests.post(
        token_endpoint,
        data={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": auth_code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        },
    )
    token_resp.raise_for_status()
    tokens = token_resp.json()
    print("Access token:", tokens.get("access_token"))
    print("Refresh token:", tokens.get("refresh_token"))

    return tokens


# ----------------------------
# Lancer l'auth
# ----------------------------
if __name__ == "__main__":
    authenticate()
















#
# import os
# from typing import Optional, Dict, Any
# from datetime import datetime, timedelta
# import httpx
# import inspect
# from .exceptions import AuthenticationError, NetworkError
# from .config import Config
#
#
# class KeycloakAuth:
#     """Handles Keycloak authentication for MecaPy API."""
#
#     async def _json(self, response: httpx.Response) -> Dict[str, Any]:
#         """Return JSON from response, awaiting if mocks return coroutine."""
#         data = response.json()
#         if inspect.isawaitable(data):
#             return await data
#         return data
#
#     def __init__(
#         self,
#         keycloak_url: str,
#         realm: str = Config.DEFAULT_REALM,
#         client_id: str = Config.DEFAULT_CLIENT_ID,
#         username: Optional[str] = None,
#         password: Optional[str] = None
#     ):
#         """
#         Initialize Keycloak authentication.
#
#         Args:
#             keycloak_url: Base URL of Keycloak server
#             realm: Keycloak realm name
#             client_id: Keycloak client ID (public client)
#             username: Username for authentication
#             password: Password for authentication
#         """
#         self.keycloak_url = keycloak_url.rstrip("/")
#         self.realm = realm
#         self.client_id = client_id
#         self.username = username
#         self.password = password
#
#         self._access_token: Optional[str] = None
#         self._token_expires_at: Optional[datetime] = None
#         self._refresh_token: Optional[str] = None
#
#         self.token_endpoint = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token"
#
#     def set_credentials(self, username: str, password: str) -> None:
#         """
#         Set authentication credentials.
#
#         Args:
#             username: Username for authentication
#             password: Password for authentication
#         """
#         self.username = username
#         self.password = password
#         # Clear existing tokens when credentials change
#         self._access_token = None
#         self._token_expires_at = None
#         self._refresh_token = None
#
#     async def get_access_token(self) -> str:
#         """
#         Get a valid access token, refreshing if necessary.
#
#         Returns:
#             Valid access token
#
#         Raises:
#             AuthenticationError: If authentication fails
#         """
#         if self._is_token_valid():
#             return self._access_token
#
#         if self._refresh_token:
#             try:
#                 await self._refresh_access_token()
#                 return self._access_token
#             except AuthenticationError:
#                 # Refresh failed, try to get new token
#                 pass
#
#         await self._get_new_token()
#         return self._access_token
#
#     def _is_token_valid(self) -> bool:
#         """Check if current token is valid and not expired."""
#         if not self._access_token or not self._token_expires_at:
#             return False
#
#         # Add 30 seconds buffer to avoid edge cases
#         return datetime.now() < (self._token_expires_at - timedelta(seconds=30))
#
#     async def _get_new_token(self) -> None:
#         """Get a new access token using username/password."""
#         if not self.username or not self.password:
#             raise AuthenticationError("Username and password are required for authentication")
#
#         data = {
#             "grant_type": "password",
#             "client_id": self.client_id,
#             "username": self.username,
#             "password": self.password,
#         }
#
#         try:
#             async with httpx.AsyncClient() as client:
#                 response = await client.post(
#                     self.token_endpoint,
#                     data=data,
#                     headers={"Content-Type": "application/x-www-form-urlencoded"}
#                 )
#
#                 if response.status_code == 401:
#                     raise AuthenticationError("Invalid username or password")
#                 elif response.status_code != 200:
#                     raise AuthenticationError(f"Authentication failed: {response.text}")
#
#                 token_data = await self._json(response)
#                 self._store_tokens(token_data)
#
#         except httpx.RequestError as e:
#             raise NetworkError(f"Network error during authentication: {str(e)}")
#
#     async def _refresh_access_token(self) -> None:
#         """Refresh access token using refresh token."""
#         if not self._refresh_token:
#             raise AuthenticationError("No refresh token available")
#
#         data = {
#             "grant_type": "refresh_token",
#             "client_id": self.client_id,
#             "refresh_token": self._refresh_token,
#         }
#
#         try:
#             async with httpx.AsyncClient() as client:
#                 response = await client.post(
#                     self.token_endpoint,
#                     data=data,
#                     headers={"Content-Type": "application/x-www-form-urlencoded"}
#                 )
#
#                 if response.status_code == 401:
#                     raise AuthenticationError("Refresh token expired or invalid")
#                 elif response.status_code != 200:
#                     raise AuthenticationError(f"Token refresh failed: {response.text}")
#
#                 token_data = await self._json(response)
#                 self._store_tokens(token_data)
#
#         except httpx.RequestError as e:
#             raise NetworkError(f"Network error during token refresh: {str(e)}")
#
#     def _store_tokens(self, token_data: Dict[str, Any]) -> None:
#         """Store tokens from authentication response."""
#         self._access_token = token_data["access_token"]
#         self._refresh_token = token_data.get("refresh_token")
#
#         # Calculate expiration time
#         expires_in = token_data.get("expires_in", 300)  # Default 5 minutes
#         self._token_expires_at = datetime.now() + timedelta(seconds=expires_in)
#
#     def logout(self) -> None:
#         """Clear stored tokens."""
#         self._access_token = None
#         self._token_expires_at = None
#         self._refresh_token = None
#
#     @classmethod
#     def from_env(cls) -> "KeycloakAuth":
#         """
#         Create KeycloakAuth instance from environment variables.
#
#         Expected environment variables:
#         - MECAPY_AUTH_URL: Keycloak server URL (optional, defaults to Config.MECAPY_AUTH_URL)
#         - MECAPY_REALM: Keycloak realm (optional, defaults to Config.DEFAULT_REALM)
#         - MECAPY_CLIENT_ID: Keycloak client ID (optional, defaults to Config.DEFAULT_CLIENT_ID)
#         - MECAPY_USERNAME: Username for authentication (optional)
#         - MECAPY_PASSWORD: Password for authentication (optional)
#
#         Returns:
#             KeycloakAuth instance
#         """
#         keycloak_url = os.getenv("MECAPY_AUTH_URL", Config.MECAPY_AUTH_URL)
#
#         return cls(
#             keycloak_url=keycloak_url,
#             realm=os.getenv("MECAPY_REALM", Config.DEFAULT_REALM),
#             client_id=os.getenv("MECAPY_CLIENT_ID", Config.DEFAULT_CLIENT_ID),
#             username=os.getenv("MECAPY_USERNAME"),
#             password=os.getenv("MECAPY_PASSWORD"),
#         )
