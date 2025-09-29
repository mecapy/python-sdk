"""Authentication module for MecaPy SDK.

Provides multiple authentication strategies inspired by PyGithub architecture:
- OAuth2: Interactive browser-based authentication with PKCE
- Token: Service account authentication with long-lived tokens
- ServiceAccount: Client credentials flow
- Default: Auto-detection from environment/keyring
"""

import http.server
import json
import os
import secrets
import socket
import urllib.parse
import webbrowser
from abc import ABC, abstractmethod
from typing import Any

import keyring
import requests
from authlib.integrations.requests_client import OAuth2Session

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


class AuthBase(ABC):
    """Abstract base class for all authentication strategies."""

    @abstractmethod
    def get_access_token(self) -> str:
        """Get a valid access token.

        Returns
        -------
        str
            Valid access token

        Raises
        ------
        AuthenticationError
            If authentication fails
        """

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        """Add authentication to a requests.PreparedRequest.

        Parameters
        ----------
        request : requests.PreparedRequest
            The request to authenticate

        Returns
        -------
        requests.PreparedRequest
            The authenticated request
        """
        token = self.get_access_token()
        request.headers["Authorization"] = f"Bearer {token}"
        return request


class TokenAuth(AuthBase):
    """Token-based authentication using long-lived service account tokens.

    This authentication method is ideal for:
    - CI/CD pipelines
    - Server-to-server communication
    - Data science workflows
    - Applications where interactive login is not practical

    Parameters
    ----------
    token : str
        Long-lived access token obtained from Keycloak service account

    Examples
    --------
    >>> from mecapy import MecaPyClient, Auth
    >>> auth = Auth.Token("your-service-account-token")
    >>> client = MecaPyClient(auth=auth)
    """

    def __init__(self, token: str) -> None:
        self.token = token.strip()
        if not self.token:
            raise ValueError("Token cannot be empty")

    def get_access_token(self) -> str:
        """Return the configured token."""
        return self.token


class ServiceAccountAuth(AuthBase):
    """Service account authentication using client credentials flow.

    Automatically obtains and refreshes tokens using Keycloak client credentials.
    Suitable for long-running applications that need automatic token management.

    Parameters
    ----------
    client_id : str
        Keycloak client ID configured for service accounts
    client_secret : str
        Keycloak client secret
    keycloak_url : str, optional
        Keycloak server URL (default from config)
    realm : str, optional
        Keycloak realm (default from config)

    Examples
    --------
    >>> from mecapy import MecaPyClient, Auth
    >>> auth = Auth.ServiceAccount(client_id="mecapy-sdk-service", client_secret="your-client-secret")
    >>> client = MecaPyClient(auth=auth)
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        keycloak_url: str | None = None,
        realm: str | None = None,
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.keycloak_url = keycloak_url or config.auth.issuer.rstrip("/")
        self.realm = realm or config.auth.realm
        self._token_cache: dict[str, Any] | None = None

    def _get_token_endpoint(self) -> str:
        """Get the token endpoint URL."""
        return f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token"

    def _fetch_token(self) -> dict[str, Any]:
        """Fetch new token using client credentials."""
        token_url = self._get_token_endpoint()
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        response = requests.post(token_url, data=data, timeout=10)
        response.raise_for_status()
        return response.json()

    def _is_token_valid(self) -> bool:
        """Check if cached token is still valid."""
        if not self._token_cache:
            return False

        # Simple expiration check (could be enhanced with JWT parsing)
        expires_in = self._token_cache.get("expires_in", 0)
        # Consider token expired if less than 60 seconds remaining
        return expires_in > 60

    def get_access_token(self) -> str:
        """Get a valid access token, refreshing if necessary."""
        if not self._is_token_valid():
            self._token_cache = self._fetch_token()

        if self._token_cache is None:
            raise NoAccessTokenError()

        access_token = self._token_cache.get("access_token")
        if not access_token:
            raise NoAccessTokenError()

        return str(access_token)


class OAuth2Auth(AuthBase):
    """
    OAuth2 authentication with Authorization Code + PKCE flow.

    This authentication method provides interactive browser-based login
    suitable for desktop applications and development environments.
    Tokens are stored securely in the system keyring.

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

    Examples
    --------
    >>> from mecapy import MecaPyClient, Auth
    >>> auth = Auth.OAuth2()
    >>> client = MecaPyClient(auth=auth)
    >>> # Browser will open for authentication
    """

    # Constants
    DEFAULT_PORTS: tuple[int, ...] = (8085, 8086, 8087, 8088, 8089)
    DEFAULT_SCOPES: tuple[str, ...] = ("openid", "profile", "email")
    KEYRING_SERVICE: str = "MecaPy"
    KEYRING_TOKEN_KEY: str = "token"  # noqa: S105
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
            s.settimeout(OAuth2Auth.SOCKET_TIMEOUT)
            try:
                s.bind((OAuth2Auth.LOCALHOST, port))
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
        resp = requests.get(discovery_url, timeout=10)
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

    def get_access_token(self) -> str:
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

    @classmethod
    def from_env(cls) -> "OAuth2Auth":
        """Create OAuth2Auth instance from environment variables.

        Returns
        -------
        OAuth2Auth
            Configured OAuth2Auth instance
        """
        return cls()


class DefaultAuth(AuthBase):
    """Default authentication that tries multiple sources in order.

    Attempts authentication in this order:
    1. Environment variable MECAPY_TOKEN
    2. Stored OAuth2 token from keyring
    3. Interactive OAuth2 login

    This provides the most convenient experience for users while supporting
    both interactive and programmatic use cases.

    Examples
    --------
    >>> from mecapy import MecaPyClient, Auth
    >>> auth = Auth.Default()
    >>> client = MecaPyClient(auth=auth)
    """

    def __init__(self) -> None:
        self._auth_strategy: AuthBase | None = None

    def _get_auth_strategy(self) -> AuthBase:
        """Get the appropriate authentication strategy."""
        if self._auth_strategy:
            return self._auth_strategy

        # 1. Try environment token
        token = os.getenv("MECAPY_TOKEN")
        if token:
            self._auth_strategy = TokenAuth(token)
            return self._auth_strategy

        # 2. Try OAuth2 with stored credentials
        oauth2_auth = OAuth2Auth()
        stored_token = oauth2_auth._retrieve_stored_token()
        if stored_token:
            self._auth_strategy = oauth2_auth
            return self._auth_strategy

        # 3. Fall back to interactive OAuth2
        self._auth_strategy = oauth2_auth
        return self._auth_strategy

    def get_access_token(self) -> str:
        """Get access token using the best available method."""
        return self._get_auth_strategy().get_access_token()


# PyGithub-style Auth namespace
class Auth:
    """Authentication methods for MecaPy SDK.

    Provides static methods to create different authentication strategies,
    following PyGithub's Auth pattern.

    Examples
    --------
    >>> from mecapy import Auth
    >>>
    >>> # Token authentication
    >>> auth = Auth.Token("your-service-account-token")
    >>>
    >>> # Service account with client credentials
    >>> auth = Auth.ServiceAccount(client_id="mecapy-sdk-service", client_secret="your-secret")
    >>>
    >>> # Interactive OAuth2
    >>> auth = Auth.OAuth2()
    >>>
    >>> # Auto-detection
    >>> auth = Auth.Default()
    """

    @staticmethod
    def Token(token: str) -> TokenAuth:  # noqa: N802
        """Create token-based authentication.

        Parameters
        ----------
        token : str
            Long-lived access token

        Returns
        -------
        TokenAuth
            Token authentication instance
        """
        return TokenAuth(token)

    @staticmethod
    def ServiceAccount(  # noqa: N802
        client_id: str,
        client_secret: str,
        keycloak_url: str | None = None,
        realm: str | None = None,
    ) -> ServiceAccountAuth:
        """Create service account authentication.

        Parameters
        ----------
        client_id : str
            Keycloak client ID
        client_secret : str
            Keycloak client secret
        keycloak_url : str, optional
            Keycloak server URL
        realm : str, optional
            Keycloak realm

        Returns
        -------
        ServiceAccountAuth
            Service account authentication instance
        """
        return ServiceAccountAuth(client_id, client_secret, keycloak_url, realm)

    @staticmethod
    def OAuth2() -> OAuth2Auth:  # noqa: N802
        """Create OAuth2 authentication.

        Returns
        -------
        OAuth2Auth
            OAuth2 authentication instance
        """
        return OAuth2Auth()

    @staticmethod
    def Default() -> DefaultAuth:  # noqa: N802
        """Create default authentication (auto-detection).

        Returns
        -------
        DefaultAuth
            Default authentication instance
        """
        return DefaultAuth()


# Backward compatibility alias
MecapyAuth = OAuth2Auth
