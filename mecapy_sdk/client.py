"""Main client for MecaPy SDK."""

import os
from typing import Optional, Dict, Any, BinaryIO, Union
from pathlib import Path
import httpx

from .auth import KeycloakAuth
from .models import UserInfo, UploadResponse, APIResponse, ProtectedResponse, AdminResponse
from .config import DEFAULT_API_URL, DEFAULT_KEYCLOAK_URL, DEFAULT_REALM, DEFAULT_CLIENT_ID, DEFAULT_TIMEOUT
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
        auth: Optional[KeycloakAuth] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        keycloak_url: Optional[str] = None,
        realm: str = DEFAULT_REALM,
        client_id: str = DEFAULT_CLIENT_ID,
        timeout: float = DEFAULT_TIMEOUT
    ):
        """
        Initialize MecaPy client.
        
        Args:
            api_url: Base URL of the MecaPy API (defaults to DEFAULT_API_URL)
            auth: KeycloakAuth instance for authentication (optional if username/password provided)
            username: Username for authentication (alternative to auth parameter)
            password: Password for authentication (alternative to auth parameter)
            keycloak_url: Keycloak server URL (defaults to DEFAULT_KEYCLOAK_URL)
            realm: Keycloak realm (defaults to DEFAULT_REALM)
            client_id: Keycloak client ID (defaults to DEFAULT_CLIENT_ID)
            timeout: Request timeout in seconds
        """
        self.api_url = (api_url or DEFAULT_API_URL).rstrip("/")
        self.timeout = timeout
        
        # Initialize authentication
        if auth is not None:
            self.auth = auth
        elif username and password:
            # Create auth from username/password
            keycloak_url = keycloak_url or DEFAULT_KEYCLOAK_URL
            self.auth = KeycloakAuth(
                keycloak_url=keycloak_url,
                realm=realm,
                client_id=client_id,
                username=username,
                password=password
            )
        else:
            self.auth = None
        
        # Create HTTP client
        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": "mecapy-sdk/0.1.0"}
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
                raise ValidationError("Request validation failed", response.status_code, response.json())
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
        return APIResponse(**response.json())
    
    async def health_check(self) -> Dict[str, str]:
        """
        Check API health status.
        
        Returns:
            Health status dictionary
        """
        response = await self._make_request("GET", "/health", authenticated=False)
        return response.json()
    
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
        return UserInfo(**response.json())
    
    async def test_protected_route(self) -> ProtectedResponse:
        """
        Test protected route access.
        
        Returns:
            Protected route response
            
        Raises:
            AuthenticationError: If not authenticated
        """
        response = await self._make_request("GET", "/auth/protected")
        return ProtectedResponse(**response.json())
    
    async def test_admin_route(self) -> AdminResponse:
        """
        Test admin route access.
        
        Returns:
            Admin route response
            
        Raises:
            AuthenticationError: If not authenticated or not admin
        """
        response = await self._make_request("GET", "/auth/admin")
        return AdminResponse(**response.json())
    
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
            file_content = file_path.read_bytes()
        else:
            # Assume it's a file-like object
            if not filename:
                raise ValidationError("filename is required when using file-like object")
            file_content = file.read()
        
        # Validate file extension
        if not filename.lower().endswith('.zip'):
            raise ValidationError("Only ZIP files are allowed")
        
        # Prepare multipart form data
        files = {
            "file": (filename, file_content, "application/zip")
        }
        
        response = await self._make_request(
            "POST", 
            "/upload/archive",
            files=files
        )
        return UploadResponse(**response.json())
    
    @classmethod
    def from_env(cls) -> "MecaPyClient":
        """
        Create MecaPyClient from environment variables.
        
        Expected environment variables:
        - MECAPY_API_URL: MecaPy API base URL (optional, defaults to DEFAULT_API_URL)
        - MECAPY_KEYCLOAK_URL: Keycloak server URL (optional, defaults to DEFAULT_KEYCLOAK_URL)
        - MECAPY_REALM: Keycloak realm (optional, defaults to DEFAULT_REALM)
        - MECAPY_CLIENT_ID: Keycloak client ID (optional, defaults to DEFAULT_CLIENT_ID)
        - MECAPY_USERNAME: Username (optional)
        - MECAPY_PASSWORD: Password (optional)
        - MECAPY_TIMEOUT: Request timeout (optional, defaults to DEFAULT_TIMEOUT)
        
        Returns:
            MecaPyClient instance with default production URLs
        """
        return cls(
            api_url=os.getenv("MECAPY_API_URL"),
            username=os.getenv("MECAPY_USERNAME"),
            password=os.getenv("MECAPY_PASSWORD"),
            keycloak_url=os.getenv("MECAPY_KEYCLOAK_URL"),
            realm=os.getenv("MECAPY_REALM", DEFAULT_REALM),
            client_id=os.getenv("MECAPY_CLIENT_ID", DEFAULT_CLIENT_ID),
            timeout=float(os.getenv("MECAPY_TIMEOUT", str(DEFAULT_TIMEOUT)))
        )