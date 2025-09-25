"""Main client for MecaPy SDK."""

import inspect
from pathlib import Path
from typing import Any, BinaryIO

import httpx

from . import version
from .auth import MecapyAuth
from .config import config
from .exceptions import AuthenticationError, NetworkError, NotFoundError, ServerError, ValidationError
from .models import AdminResponse, APIResponse, ProtectedResponse, UploadResponse, UserInfo


class MecaPyClient:
    """Main client for interacting with MecaPy API."""

    def __init__(self, api_url: str | None = None, timeout: float | None = None):
        self.auth = MecapyAuth()
        self.api_url = (api_url or config.api_url).rstrip("/")
        self.timeout = timeout or config.timeout
        # Create HTTP client
        self._client = httpx.AsyncClient(timeout=self.timeout, headers={"User-Agent": f"mecapy-sdk/{version}"})

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def _json(self, response: httpx.Response) -> dict[str, Any]:
        """Return JSON from response, awaiting if caller provide a coroutine."""
        data = response.json()
        if inspect.isawaitable(data):
            return await data
        return data

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

    async def _handle_authentication(self, headers: dict[str, str]) -> None:
        """Add authentication header if required."""
        try:
            token = await self.auth.get_access_token()
            headers["Authorization"] = f"Bearer {token}"
        except Exception as e:
            raise AuthenticationError(f"Failed to get access token: {str(e)}")

    def _handle_response_errors(self, response: httpx.Response) -> None:
        """Handle HTTP response errors based on status codes."""
        match response.status_code:
            case 401:
                raise AuthenticationError("Authentication failed")
            case 403:
                raise AuthenticationError("Access forbidden")
            case 404:
                raise NotFoundError("Resource not found")
            case 422:
                raise ValidationError("Request validation failed", response.status_code, response.json())
            case code if 400 <= code < 500:
                raise ValidationError(f"Client error: {response.text}", response.status_code)
            case code if code >= 500:
                raise ServerError(f"Server error: {response.text}", response.status_code)

    async def _prepare_file_upload(self, file: str | Path | BinaryIO, filename: str | None) -> tuple[str, bytes]:
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

    async def _make_request(self, method: str, endpoint: str, authenticated: bool = True, **kwargs) -> httpx.Response:
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
        httpx.Response
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
        headers = kwargs.pop("headers", {})

        # Add authentication header if required
        if authenticated and self.auth:
            await self._handle_authentication(headers)

        try:
            response = await self._client.request(method=method, url=url, headers=headers, **kwargs)
            self._handle_response_errors(response)
            return response
        except httpx.RequestError as e:
            raise NetworkError(f"Network error: {str(e)}")

    async def get_root(self) -> APIResponse:
        """
        Get API root information.

        Returns
        -------
            API response with basic information
        """
        response = await self._make_request("GET", "/", authenticated=False)
        data = await self._json(response)
        return APIResponse(**data)

    async def health_check(self) -> dict[str, str]:
        """
        Check API health status.

        Returns
        -------
            Health status dictionary
        """
        response = await self._make_request("GET", "/health", authenticated=False)
        return await self._json(response)

    async def get_current_user(self) -> UserInfo:
        """
        Get information about the currently authenticated user.

        Returns
        -------
            Current user information

        Raises
        ------
            AuthenticationError: If not authenticated
        """
        response = await self._make_request("GET", "/auth/me")
        data = await self._json(response)
        # Normalize production variants: some deployments may return `username` instead of `preferred_username`
        data = self._normalize_username_field(data)
        return UserInfo(**data)

    async def test_protected_route(self) -> ProtectedResponse:
        """
        Test protected route access.

        Returns
        -------
            Protected route response

        Raises
        ------
            AuthenticationError: If not authenticated
        """
        response = await self._make_request("GET", "/auth/protected")
        data = await self._json(response)
        # Normalize production variants for nested user_info
        data = self._normalize_nested_user_info(data)
        return ProtectedResponse(**data)

    async def test_admin_route(self) -> AdminResponse:
        """
        Test admin route access.

        Returns
        -------
            Admin route response

        Raises
        ------
            AuthenticationError: If not authenticated or not admin
        """
        response = await self._make_request("GET", "/auth/admin")
        data = await self._json(response)
        return AdminResponse(**data)

    # Upload endpoints
    async def upload_archive(self, file: str | Path | BinaryIO, filename: str | None = None) -> UploadResponse:
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
        filename, file_content = await self._prepare_file_upload(file, filename)

        # Prepare multipart form data
        files = {"file": (filename, file_content, "application/zip")}

        response = await self._make_request("POST", "/upload/archive", files=files)
        data = await self._json(response)
        return UploadResponse(**data)
