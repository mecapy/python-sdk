"""Main client for MecaPy SDK."""

import os
from typing import Optional, Dict, Any, BinaryIO, Union
from pathlib import Path
import httpx
import inspect

from .auth import MecapyAuth
from .models import UserInfo, UploadResponse, APIResponse, ProtectedResponse, AdminResponse
from .config import config
from .__version__ import __version__
from .exceptions import (
    MecaPyError, 
    AuthenticationError, 
    ValidationError, 
    NotFoundError, 
    ServerError, 
    NetworkError
)


class MecaPyClient:
    """Main client for interacting with MecaPy API."""
    
    def __init__(
        self,
        api_url: Optional[str] = None,
        auth: Optional[MecapyAuth] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: float = config.timeout
    ):
        """
        Initialize MecaPy client.

        Args:
            api_url: Base URL of the MecaPy API (defaults to config.api_url)
            auth: MecapyAuth instance for authentication (optional if username/password provided)
            username: Username for authentication (alternative to auth parameter)
            password: Password for authentication (alternative to auth parameter)
            timeout: Request timeout in seconds
        """
        self.api_url = (api_url or config.api_url).rstrip("/")
        self.timeout = timeout

        # Initialize authentication
        if auth is not None:
            self.auth = auth
        elif username and password:
            # Create auth instance - it will use global config for OIDC settings
            self.auth = MecapyAuth()
            # Note: MecapyAuth uses OAuth2 + PKCE flow, not username/password directly
            # This is for backward compatibility, but users should use the web flow
        else:
            self.auth = None
        
        # Create HTTP client
        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": f"mecapy-sdk/{__version__}"}
        )
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
    
    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
    
    async def _json(self, response: httpx.Response) -> Dict[str, Any]:
        """Return JSON from response, awaiting if the test/mocks provide a coroutine."""
        data = response.json()
        if inspect.isawaitable(data):
            return await data
        return data

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        authenticated: bool = True,
        **kwargs
    ) -> httpx.Response:
        """
        Make an HTTP request to the API.
        
        Args:
            method: HTTP method
            endpoint: API endpoint (without base URL)
            authenticated: Whether to include authentication headers
            **kwargs: Additional arguments for httpx request
            
        Returns:
            HTTP response
            
        Raises:
            Various MecaPy exceptions based on response status
        """
        url = f"{self.api_url}{endpoint}"
        headers = kwargs.pop("headers", {})
        
        # Add authentication header if required
        if authenticated and self.auth:
            try:
                token = await self.auth.get_access_token()
                headers["Authorization"] = f"Bearer {token}"
            except Exception as e:
                raise AuthenticationError(f"Failed to get access token: {str(e)}")
        
        try:
            response = await self._client.request(
                method=method,
                url=url,
                headers=headers,
                **kwargs
            )
            
            # Handle different status codes
            if response.status_code == 401:
                raise AuthenticationError("Authentication failed")
            elif response.status_code == 403:
                raise AuthenticationError("Access forbidden")
            elif response.status_code == 404:
                raise NotFoundError("Resource not found")
            elif response.status_code == 422:
                raise ValidationError("Request validation failed", response.status_code, await self._json(response))
            elif 400 <= response.status_code < 500:
                raise ValidationError(f"Client error: {response.text}", response.status_code)
            elif response.status_code >= 500:
                raise ServerError(f"Server error: {response.text}", response.status_code)
            
            return response
            
        except httpx.RequestError as e:
            raise NetworkError(f"Network error: {str(e)}")
    
    # API Root endpoints
    async def get_root(self) -> APIResponse:
        """
        Get API root information.
        
        Returns:
            API response with basic information
        """
        response = await self._make_request("GET", "/", authenticated=False)
        data = await self._json(response)
        return APIResponse(**data)
    
    async def health_check(self) -> Dict[str, str]:
        """
        Check API health status.
        
        Returns:
            Health status dictionary
        """
        response = await self._make_request("GET", "/health", authenticated=False)
        return await self._json(response)
    
    # Authentication endpoints
    async def get_current_user(self) -> UserInfo:
        """
        Get information about the currently authenticated user.
        
        Returns:
            Current user information
            
        Raises:
            AuthenticationError: If not authenticated
        """
        response = await self._make_request("GET", "/auth/me")
        data = await self._json(response)
        # Normalize production variants: some deployments may return `username` instead of `preferred_username`
        if isinstance(data, dict):
            if "preferred_username" not in data and "username" in data:
                # Avoid mutating the original dict if it's shared
                data = dict(data)
                data["preferred_username"] = data["username"]
        return UserInfo(**data)
    
    async def test_protected_route(self) -> ProtectedResponse:
        """
        Test protected route access.
        
        Returns:
            Protected route response
            
        Raises:
            AuthenticationError: If not authenticated
        """
        response = await self._make_request("GET", "/auth/protected")
        data = await self._json(response)
        # Normalize production variants for nested user_info
        if isinstance(data, dict):
            ui = data.get("user_info")
            if isinstance(ui, dict) and "preferred_username" not in ui and "username" in ui:
                ui = dict(ui)
                ui["preferred_username"] = ui["username"]
                data = dict(data)
                data["user_info"] = ui
        return ProtectedResponse(**data)
    
    async def test_admin_route(self) -> AdminResponse:
        """
        Test admin route access.
        
        Returns:
            Admin route response
            
        Raises:
            AuthenticationError: If not authenticated or not admin
        """
        response = await self._make_request("GET", "/auth/admin")
        data = await self._json(response)
        return AdminResponse(**data)
    
    # Upload endpoints
    async def upload_archive(
        self, 
        file: Union[str, Path, BinaryIO],
        filename: Optional[str] = None
    ) -> UploadResponse:
        """
        Upload a ZIP archive to the API.
        
        Args:
            file: File path, Path object, or file-like object
            filename: Override filename (if file is file-like object)
            
        Returns:
            Upload response with file information
            
        Raises:
            ValidationError: If file is not a ZIP file
            AuthenticationError: If not authenticated
        """
        # Handle different file input types
        if isinstance(file, (str, Path)):
            file_path = Path(file)
            if not file_path.exists():
                raise ValidationError(f"File not found: {file_path}")
            
            filename = filename or file_path.name
        else:
            # Assume it's a file-like object
            if not filename:
                raise ValidationError("filename is required when using file-like object")
        
        # Validate file extension
        if not filename.lower().endswith('.zip'):
            raise ValidationError("Only ZIP files are allowed")
        
        # Read file content after validation
        if isinstance(file, (str, Path)):
            file_content = file_path.read_bytes()
        else:
            file_content = file.read()
        
        # Prepare multipart form data
        files = {
            "file": (filename, file_content, "application/zip")
        }
        
        response = await self._make_request(
            "POST", 
            "/upload/archive",
            files=files
        )
        data = await self._json(response)
        return UploadResponse(**data)
    
    @classmethod
    def from_env(cls) -> "MecaPyClient":
        """
        Create MecaPyClient from environment variables.
        
        Expected environment variables:
        - MECAPY_API_URL: MecaPy API base URL (optional, defaults to Config.MECAPY_API_URL)
        - MECAPY_AUTH_URL: Keycloak server URL (optional, defaults to Config.MECAPY_AUTH_URL)
        - MECAPY_REALM: Keycloak realm (optional, defaults to Config.DEFAULT_REALM)
        - MECAPY_CLIENT_ID: Keycloak client ID (optional, defaults to Config.DEFAULT_CLIENT_ID)
        - MECAPY_USERNAME: Username (optional)
        - MECAPY_PASSWORD: Password (optional)
        - MECAPY_TIMEOUT: Request timeout (optional, defaults to Config.DEFAULT_TIMEOUT)
        
        Returns:
            MecaPyClient instance with default production URLs
        """
        return cls(
            api_url=os.getenv("MECAPY_API_URL", config.api_url),
            username=os.getenv("MECAPY_USERNAME"),
            password=os.getenv("MECAPY_PASSWORD"),
            timeout=float(os.getenv("MECAPY_TIMEOUT", str(config.timeout)))
        )