"""Authentication module for MecaPy SDK."""

import os
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import httpx
from .exceptions import AuthenticationError, NetworkError


class KeycloakAuth:
    """Handles Keycloak authentication for MecaPy API."""
    
    def __init__(
        self,
        keycloak_url: str,
        realm: str = "mecapy",
        client_id: str = "mecapy-api-public",
        username: Optional[str] = None,
        password: Optional[str] = None
    ):
        """
        Initialize Keycloak authentication.
        
        Args:
            keycloak_url: Base URL of Keycloak server
            realm: Keycloak realm name
            client_id: Keycloak client ID (public client)
            username: Username for authentication
            password: Password for authentication
        """
        self.keycloak_url = keycloak_url.rstrip("/")
        self.realm = realm
        self.client_id = client_id
        self.username = username
        self.password = password
        
        self._access_token: Optional[str] = None
        self._token_expires_at: Optional[datetime] = None
        self._refresh_token: Optional[str] = None
        
        self.token_endpoint = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token"
    
    def set_credentials(self, username: str, password: str) -> None:
        """
        Set authentication credentials.
        
        Args:
            username: Username for authentication
            password: Password for authentication
        """
        self.username = username
        self.password = password
        # Clear existing tokens when credentials change
        self._access_token = None
        self._token_expires_at = None
        self._refresh_token = None
    
    async def get_access_token(self) -> str:
        """
        Get a valid access token, refreshing if necessary.
        
        Returns:
            Valid access token
            
        Raises:
            AuthenticationError: If authentication fails
        """
        if self._is_token_valid():
            return self._access_token
        
        if self._refresh_token:
            try:
                await self._refresh_access_token()
                return self._access_token
            except AuthenticationError:
                # Refresh failed, try to get new token
                pass
        
        await self._get_new_token()
        return self._access_token
    
    def _is_token_valid(self) -> bool:
        """Check if current token is valid and not expired."""
        if not self._access_token or not self._token_expires_at:
            return False
        
        # Add 30 seconds buffer to avoid edge cases
        return datetime.now() < (self._token_expires_at - timedelta(seconds=30))
    
    async def _get_new_token(self) -> None:
        """Get a new access token using username/password."""
        if not self.username or not self.password:
            raise AuthenticationError("Username and password are required for authentication")
        
        data = {
            "grant_type": "password",
            "client_id": self.client_id,
            "username": self.username,
            "password": self.password,
        }
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.token_endpoint,
                    data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                
                if response.status_code == 401:
                    raise AuthenticationError("Invalid username or password")
                elif response.status_code != 200:
                    raise AuthenticationError(f"Authentication failed: {response.text}")
                
                token_data = response.json()
                self._store_tokens(token_data)
                
        except httpx.RequestError as e:
            raise NetworkError(f"Network error during authentication: {str(e)}")
    
    async def _refresh_access_token(self) -> None:
        """Refresh access token using refresh token."""
        if not self._refresh_token:
            raise AuthenticationError("No refresh token available")
        
        data = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "refresh_token": self._refresh_token,
        }
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.token_endpoint,
                    data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                
                if response.status_code == 401:
                    raise AuthenticationError("Refresh token expired or invalid")
                elif response.status_code != 200:
                    raise AuthenticationError(f"Token refresh failed: {response.text}")
                
                token_data = response.json()
                self._store_tokens(token_data)
                
        except httpx.RequestError as e:
            raise NetworkError(f"Network error during token refresh: {str(e)}")
    
    def _store_tokens(self, token_data: Dict[str, Any]) -> None:
        """Store tokens from authentication response."""
        self._access_token = token_data["access_token"]
        self._refresh_token = token_data.get("refresh_token")
        
        # Calculate expiration time
        expires_in = token_data.get("expires_in", 300)  # Default 5 minutes
        self._token_expires_at = datetime.now() + timedelta(seconds=expires_in)
    
    def logout(self) -> None:
        """Clear stored tokens."""
        self._access_token = None
        self._token_expires_at = None
        self._refresh_token = None
    
    @classmethod
    def from_env(cls) -> "KeycloakAuth":
        """
        Create KeycloakAuth instance from environment variables.
        
        Expected environment variables:
        - MECAPY_KEYCLOAK_URL: Keycloak server URL (optional, defaults to 'https://auth.mecapy.com')
        - MECAPY_REALM: Keycloak realm (optional, defaults to 'mecapy')
        - MECAPY_CLIENT_ID: Keycloak client ID (optional, defaults to 'mecapy-api-public')
        - MECAPY_USERNAME: Username for authentication (optional)
        - MECAPY_PASSWORD: Password for authentication (optional)
        
        Returns:
            KeycloakAuth instance
        """
        keycloak_url = os.getenv("MECAPY_KEYCLOAK_URL", "https://auth.mecapy.com")
        
        return cls(
            keycloak_url=keycloak_url,
            realm=os.getenv("MECAPY_REALM", "mecapy"),
            client_id=os.getenv("MECAPY_CLIENT_ID", "mecapy-api-public"),
            username=os.getenv("MECAPY_USERNAME"),
            password=os.getenv("MECAPY_PASSWORD"),
        )