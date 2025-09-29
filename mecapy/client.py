"""Main client for MecaPy SDK."""

from pathlib import Path
from typing import Any, BinaryIO

import requests

from . import version
from .auth import AuthBase, DefaultAuth
from .config import config
from .exceptions import (
    AuthenticationError,
    NetworkError,
    NotFoundError,
    ServerError,
    ValidationError,
)
from .models import (
    AdminResponse,
    APIResponse,
    ProtectedResponse,
    UploadResponse,
    UserInfo,
)


class MecaPyClient:
    """Main client for interacting with MecaPy API.

    Now uses synchronous requests for better compatibility with data science workflows.

    Parameters
    ----------
    api_url : str, optional
        MecaPy API base URL (default from config)
    auth : AuthBase, optional
        Authentication strategy (default: auto-detection)
    timeout : float, optional
        Request timeout in seconds (default from config)

    Examples
    --------
    >>> from mecapy import MecaPyClient, Auth
    >>>
    >>> # Simple usage with auto-detection
    >>> client = MecaPyClient()
    >>>
    >>> # With token authentication
    >>> auth = Auth.Token("your-service-account-token")
    >>> client = MecaPyClient(auth=auth)
    >>>
    >>> # With service account
    >>> auth = Auth.ServiceAccount(client_id="mecapy-sdk-service", client_secret="your-secret")
    >>> client = MecaPyClient(auth=auth)
    """

    def __init__(self, api_url: str | None = None, auth: AuthBase | None = None, timeout: float | None = None):
        self.auth = auth or DefaultAuth()
        self.api_url = (api_url or config.api_url).rstrip("/")
        self.timeout = timeout or config.timeout
        # Create HTTP session
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": f"mecapy-sdk/{version}"})

    def __enter__(self):  # type: ignore
        """Context manager entry (optional)."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):  # type: ignore
        """Context manager exit (optional)."""
        self.close()

    def close(self) -> None:
        """Close the HTTP session (optional cleanup)."""
        self._session.close()

    def __del__(self) -> None:
        """Cleanup session on garbage collection."""
        try:
            self.close()
        except Exception:
            # Ignore errors during cleanup
            pass

    @classmethod
    def from_env(cls, api_url: str | None = None, timeout: float | None = None) -> "MecaPyClient":
        """Create client with default authentication from environment.

        Backward compatibility method.

        Parameters
        ----------
        api_url : str, optional
            MecaPy API base URL
        timeout : float, optional
            Request timeout

        Returns
        -------
        MecaPyClient
            Configured client instance
        """
        return cls(api_url=api_url, timeout=timeout)

    @classmethod
    def from_token(cls, token: str, api_url: str | None = None, timeout: float | None = None) -> "MecaPyClient":
        """Create client with token authentication.

        Parameters
        ----------
        token : str
            Long-lived access token
        api_url : str, optional
            MecaPy API base URL
        timeout : float, optional
            Request timeout

        Returns
        -------
        MecaPyClient
            Configured client instance
        """
        from .auth import Auth

        auth = Auth.Token(token)
        return cls(api_url=api_url, auth=auth, timeout=timeout)

    def _json(self, response: requests.Response) -> dict[str, Any]:
        """Return JSON from response."""
        return response.json()

    def _normalize_username_field(self, data: dict) -> dict:
        """Normalize username field in response data."""
        if isinstance(data, dict) and "preferred_username" not in data and "username" in data:
            data = dict(data)
            data["preferred_username"] = data["username"]
        return data

    def _normalize_nested_user_info(self, data: dict) -> dict:
        """Normalize username field in nested user_info."""
        if isinstance(data, dict):
            ui = data.get("user_info")
            if isinstance(ui, dict) and "preferred_username" not in ui and "username" in ui:
                ui = dict(ui)
                ui["preferred_username"] = ui["username"]
                data = dict(data)
                data["user_info"] = ui
        return data

    def _handle_authentication(self, request: requests.PreparedRequest) -> None:
        """Add authentication to request if required."""
        try:
            self.auth(request)
        except Exception as e:
            raise AuthenticationError(f"Failed to authenticate request: {str(e)}") from e

    def _handle_response_errors(self, response: requests.Response) -> None:  # noqa: C901
        """Handle HTTP response errors based on status codes."""
        if response.status_code == 401:
            raise AuthenticationError("Authentication failed")
        if response.status_code == 403:
            raise AuthenticationError("Access forbidden")
        if response.status_code == 404:
            raise NotFoundError("Resource not found")
        if response.status_code == 422:
            raise ValidationError("Request validation failed", response.status_code, response.json())
        if 400 <= response.status_code < 500:
            raise ValidationError(f"Client error: {response.text}", response.status_code)
        if response.status_code >= 500:
            raise ServerError(f"Server error: {response.text}", response.status_code)

    def _prepare_file_upload(self, file: str | Path | BinaryIO, filename: str | None) -> tuple[str, bytes]:
        """Prepare file for upload, returning filename and content."""
        if isinstance(file, (str, Path)):
            file_path = Path(file)
            if not file_path.exists():
                raise ValidationError(f"File not found: {file_path}")
            filename = filename or file_path.name
            file_content = file_path.read_bytes()
        else:
            # Assume it's a file-like object
            if not filename:
                raise ValidationError("filename is required when using file-like object")
            file_content = file.read()

        # Validate file extension
        if not filename.lower().endswith(".zip"):
            raise ValidationError("Only ZIP files are allowed")

        return filename, file_content

    def _make_request(self, method: str, endpoint: str, authenticated: bool = True, **kwargs: Any) -> requests.Response:
        """
        Make an HTTP request to the MecaPy API.

        This method constructs and executes an HTTP request using the given HTTP method
        and endpoint. It allows optional authentication and handles various response
        status codes accordingly, raising appropriate exceptions for error scenarios.
        Headers and other keyword arguments can be customized for the request.

        Parameters
        ----------
        method : str
            HTTP method to be used for the request (e.g., "GET", "POST").
        endpoint : str
            API endpoint to send the request to, relative to the base API URL (starts with "/").
        authenticated : bool, optional
            Whether the request requires authentication, by default True.
        kwargs : dict
            Additional keyword arguments to pass to the HTTP client request.

        Returns
        -------
        requests.Response
            The HTTP response object returned from the request.

        Raises
        ------
        AuthenticationError
            If an authentication-related issue occurs, such as failed token retrieval
            or invalid credentials.
        NotFoundError
            If the requested resource is not found (HTTP status 404).
        ValidationError
            If the request fails validation (e.g., client errors or unprocessable
            entities, with HTTP statuses 422 or 400-499).
        ServerError
            If the server encounters an internal issue (HTTP status 500+).
        NetworkError
            If a network-related issue prevents the request from completing.
        """
        url = f"{self.api_url}{endpoint}"

        # Prepare request
        request = requests.Request(method=method, url=url, **kwargs)
        prepared = self._session.prepare_request(request)

        # Add authentication if required
        if authenticated and self.auth:
            self._handle_authentication(prepared)

        try:
            response = self._session.send(prepared, timeout=self.timeout)
        except requests.RequestException as e:
            raise NetworkError(f"Network error: {str(e)}") from e
        else:
            self._handle_response_errors(response)
            return response

    def get_root(self) -> APIResponse:
        """
        Get API root information.

        Returns
        -------
            API response with basic information
        """
        response = self._make_request("GET", "/", authenticated=False)
        data = self._json(response)
        return APIResponse(**data)

    def health_check(self) -> dict[str, str]:
        """
        Check API health status.

        Returns
        -------
            Health status dictionary
        """
        response = self._make_request("GET", "/health", authenticated=False)
        return self._json(response)

    def get_current_user(self) -> UserInfo:
        """
        Get information about the currently authenticated user.

        Returns
        -------
            Current user information

        Raises
        ------
            AuthenticationError: If not authenticated
        """
        response = self._make_request("GET", "/auth/me")
        data = self._json(response)
        # Normalize production variants: some deployments may return `username` instead of `preferred_username`
        data = self._normalize_username_field(data)
        return UserInfo(**data)

    def test_protected_route(self) -> ProtectedResponse:
        """
        Test protected route access.

        Returns
        -------
            Protected route response

        Raises
        ------
            AuthenticationError: If not authenticated
        """
        response = self._make_request("GET", "/auth/protected")
        data = self._json(response)
        # Normalize production variants for nested user_info
        data = self._normalize_nested_user_info(data)
        return ProtectedResponse(**data)

    def test_admin_route(self) -> AdminResponse:
        """
        Test admin route access.

        Returns
        -------
            Admin route response

        Raises
        ------
            AuthenticationError: If not authenticated or not admin
        """
        response = self._make_request("GET", "/auth/admin")
        data = self._json(response)
        return AdminResponse(**data)

    # Upload endpoints
    def upload_archive(self, file: str | Path | BinaryIO, filename: str | None = None) -> UploadResponse:
        """
        Upload a ZIP archive to the API.

        Args:
            file: File path, Path object, or file-like object
            filename: Override filename (if file is file-like object)

        Returns
        -------
            Upload response with file information

        Raises
        ------
            ValidationError: If file is not a ZIP file
            AuthenticationError: If not authenticated
        """
        filename, file_content = self._prepare_file_upload(file, filename)

        # Prepare multipart form data
        files = {"file": (filename, file_content, "application/zip")}

        response = self._make_request("POST", "/upload/archive", files=files)
        data = self._json(response)
        return UploadResponse(**data)
