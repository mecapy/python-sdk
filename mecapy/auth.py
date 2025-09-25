"""Authentication module (Authorization Code + PKCE) for MecaPy SDK."""

import http.server
import json
import secrets
import socket
import urllib.parse
import webbrowser
from typing import Any

import keyring
import requests  # type: ignore[import-untyped]
from authlib.integrations.requests_client import OAuth2Session  # type: ignore[import-untyped]

from .config import config
from .exceptions import NoAccessTokenError, NoAuthCodeError, NoFreePortError


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

    def do_GET(self) -> None:
        """Handle HTTP GET requests to extract a query parameter `code` from the URL path."""
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        code = params.get("code")
        if code:
            # Store auth code in server instance (dynamically added attribute)
            self.server.auth_code = str(code[0])  # type: ignore[attr-defined]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<h1>Authentication successful!</h1><p>You can close this window.</p>")
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"<h1>Error: code not found</h1>")


class MecapyAuth:
    """
    Handles authentication and token management for the MecaPy SDK.

    This class implements OAuth2 flows, token storage, and session management for
    seamless interaction with the MecaPy system's authentication mechanism.
    It provides methods to log in, log out, retrieve tokens, manage OAuth2 sessions,
    and interact with the Keycloak authorization and token endpoints.

    Attributes
    ----------
    DEFAULT_PORTS : tuple[int]
        Default list of ports (`8085` - `8089`) to be used for local server callback.
    DEFAULT_SCOPES : tuple[str]
        Default scopes for the OAuth2 authorization process, including `openid`,
        `profile`, and `email`.
    KEYRING_SERVICE : str
        Name of the keyring service for secure token storage, set to "MecaPy".
    KEYRING_TOKEN_KEY : str
        Key identifier used for storing and retrieving token data in the keyring.
    LOCALHOST : str
        Localhost IP address used for binding the local HTTP server, set to
        `127.0.0.1`.
    SOCKET_TIMEOUT : float
        Timeout in seconds for checking port availability, set to `0.5`.
    CODE_VERIFIER_LENGTH : int
        Length of the code verifier string for PKCE (Proof Key for Code Exchange),
        set to `48`.
    CODE_CHALLENGE_METHOD : str
        PKCE code challenge method, set to `"S256"`.
    """

    # Constants
    DEFAULT_PORTS: tuple[int, ...] = (8085, 8086, 8087, 8088, 8089)
    DEFAULT_SCOPES: tuple[str, ...] = ("openid", "profile", "email")
    KEYRING_SERVICE: str = "MecaPy"
    KEYRING_TOKEN_KEY: str = "token"
    LOCALHOST: str = "127.0.0.1"
    SOCKET_TIMEOUT: float = 0.5
    CODE_VERIFIER_LENGTH: int = 48
    CODE_CHALLENGE_METHOD: str = "S256"

    def __init__(self) -> None:
        self.client_id = config.auth.client_id
        self.realm = config.auth.realm
        self.issuer = config.auth.issuer
        self.scopes = list(self.DEFAULT_SCOPES)
        self.port = self.set_port(*self.DEFAULT_PORTS)
        self.redirect_uri = f"http://localhost:{self.port}/callback"
        self.auth_code = None
        oidc_conf = self.fetch_oidc_config()
        self.authorization_endpoint = oidc_conf["authorization_endpoint"]
        self.token_endpoint = oidc_conf["token_endpoint"]

    def set_port(self, *ports: int) -> int:
        """
        Select and sets a free port from the provided list of ports.

        This method iterates through the provided port arguments and checks
        each one to determine if it is free using the `is_port_free` method.
        If a free port is found, it is returned. If no free port is available,
        an exception is raised.

        Parameters
        ----------
        ports : int
            A list of port numbers to evaluate for availability.

        Returns
        -------
        int
            The first available port from the provided list of ports.

        Raises
        ------
        RuntimeError
            If no free port is found in the provided list.
        """
        for port in ports:
            if self.is_port_free(port):
                return port
        raise NoFreePortError(ports)

    @staticmethod
    def is_port_free(port: int) -> bool:
        """
        Determine if a given network port on the localhost is free to use.

        This method checks the availability of a specific port on the localhost by
        attempting to bind to it. If the bind operation is successful, the port is
        considered free; otherwise, it is considered occupied.

        Parameters
        ----------
        port : int
            The port number to check for availability on the localhost.

        Returns
        -------
        bool
            True if the port is available (free), False if it is currently in use.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(MecapyAuth.SOCKET_TIMEOUT)
            try:
                s.bind((MecapyAuth.LOCALHOST, port))
            except OSError:
                return False
            else:
                return True

    def fetch_oidc_config(self) -> dict[str, Any]:
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
        discovery_url = config.auth.get_oidc_discovery_url()
        resp = requests.get(discovery_url)
        resp.raise_for_status()
        return resp.json()

    def waiting_for_code(self) -> str:
        """
        Handle the OAuth2 callback to retrieve the authorization code from the Keycloak server.

        This function starts a local HTTP server to listen for the redirection from the Keycloak
        authorization endpoint. The authorization code is extracted from the received callback
        and returned for further processing.

        If no authorization code is received during the callback, an exception is raised.

        Returns
        -------
        str
            The authorization code received from the authorization server.

        Raises
        ------
        RuntimeError
            If no authorization code is received from the authorization server.
        """
        # Démarrer serveur local
        with http.server.HTTPServer(("localhost", self.port), OAuthCallbackHandler) as server:
            server.handle_request()
            auth_code = getattr(server, "auth_code", None)
        if auth_code:
            return auth_code
        raise NoAuthCodeError()

    def _create_oauth_client(self, token: dict[str, Any] | None = None) -> OAuth2Session:
        """
        Create an OAuth2Session client with common configuration.

        Parameters
        ----------
        token : dict, optional
            Existing token data to initialize the client with

        Returns
        -------
        OAuth2Session
            Configured OAuth2Session client
        """
        return OAuth2Session(
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            token_endpoint=self.token_endpoint,
            code_challenge_method=self.CODE_CHALLENGE_METHOD,
            token=token,
        )

    def _store_token(self, token: dict[str, Any]) -> None:
        """
        Store token in keyring.

        Parameters
        ----------
        token : dict
            Token data to store
        """
        keyring.set_password(self.KEYRING_SERVICE, self.KEYRING_TOKEN_KEY, json.dumps(token))

    def _retrieve_stored_token(self) -> dict[str, Any] | None:
        """
        Retrieve token from keyring.

        Returns
        -------
        dict | None
            Token data if found, None otherwise
        """
        token_as_str = keyring.get_password(self.KEYRING_SERVICE, self.KEYRING_TOKEN_KEY)
        return json.loads(token_as_str) if token_as_str else None

    def _clear_stored_token(self) -> None:
        """Clear token from keyring."""
        keyring.delete_password(self.KEYRING_SERVICE, self.KEYRING_TOKEN_KEY)

    def login(self) -> dict[str, Any]:
        """
        Login user through OAuth2 flow with Authorization Code + PKCE.

        Authenticate the user through an OAuth2 flow by opening a browser for login,
        exchanging an authorization code for an access token, and storing the token securely.

        Returns
        -------
        dict
            The OAuth2 token containing access and optionally refresh tokens.
        """
        client = self._create_oauth_client()
        code_verifier = secrets.token_urlsafe(self.CODE_VERIFIER_LENGTH)

        # URL d'autorisation
        uri, state = client.create_authorization_url(self.authorization_endpoint, code_verifier=code_verifier)
        print("Opening browser for login:", uri)
        webbrowser.open(uri)

        # Attend le code via le mini serveur local
        auth_code = self.waiting_for_code()

        # Échange code contre token
        token_data = client.fetch_token(self.token_endpoint, code=auth_code, code_verifier=code_verifier)

        # Sauvegarde dans keyring
        self._store_token(token_data)

        return token_data

    def logout(self) -> None:
        """Log the user out by revoking their access and refresh tokens and clearing stored tokens."""
        client = self.get_session()
        for tth in ("access_token", "refresh_token"):
            if tth in client.token:
                client.revoke_token(self.token_endpoint, token=client.token[tth], token_type_hint=tth)
        self._clear_stored_token()

    def get_token(self) -> dict[str, Any]:
        """
        Retrieve a stored token or generates a new one if none exists.

        Checks for a stored token using an internal method. If no token is found,
        initiates the login process to retrieve a new one.

        Returns
        -------
        dict
            A dictionary representing the token retrieved or generated.
        """
        token = self._retrieve_stored_token()
        if token is None:
            return self.login()
        return token

    def get_session(self) -> "OAuth2Session":
        """
        Retrieve and ensure an active OAuth2 session.

        This method gets an OAuth2 token and creates an OAuth2 session. It ensures
        that the session's token is active and valid. If the token is expired or
        invalid, it attempts to log in again to acquire a new token and creates a
        new OAuth2 session using the updated token.

        Returns
        -------
        OAuth2Session
            An OAuth2 session instance with a valid and active token.
        """
        token = self.get_token()
        session = self._create_oauth_client(token=token)
        try:
            session.ensure_active_token()
        except Exception:  # Catch broad exception for OAuth errors
            token = self.login()
            return self._create_oauth_client(token=token)
        else:
            return session

    async def get_access_token(self) -> str:
        """
        Get access token for compatibility with existing client code.

        Returns
        -------
        str
            The access token string

        Raises
        ------
        ValueError
            If no access token is found in the token response
        """
        token_data = self.get_token()
        access_token = token_data.get("access_token")
        if not access_token:
            raise NoAccessTokenError()
        return str(access_token)
