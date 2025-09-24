"""Tests for authentication module."""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from mecapy.auth import MecapyAuth
from mecapy.exceptions import AuthenticationError, NetworkError


@pytest.mark.unit
class TestMecapyAuth:
    """Test MecapyAuth class."""

    def test_init(self):
        """Test MecapyAuth initialization."""
        auth = MecapyAuth(
            keycloak_url="https://auth.example.com",
            realm="test-realm",
            client_id="test-client",
            username="testuser",
            password="testpass",
        )

        assert auth.keycloak_url == "https://auth.example.com"
        assert auth.realm == "test-realm"
        assert auth.client_id == "test-client"
        assert auth.username == "testuser"
        assert auth.password == "testpass"
        assert auth.token_endpoint == "https://auth.example.com/realms/test-realm/protocol/openid-connect/token"

    def test_init_strips_trailing_slash(self):
        """Test that trailing slash is stripped from Keycloak URL."""
        auth = MecapyAuth(keycloak_url="https://auth.example.com/", realm="test")
        assert auth.keycloak_url == "https://auth.example.com"

    def test_set_credentials(self):
        """Test setting credentials."""
        auth = MecapyAuth("https://auth.example.com")
        auth._access_token = "old_token"
        auth._token_expires_at = datetime.now() + timedelta(hours=1)

        auth.set_credentials("newuser", "newpass")

        assert auth.username == "newuser"
        assert auth.password == "newpass"
        assert auth._access_token is None
        assert auth._token_expires_at is None

    def test_is_token_valid_no_token(self):
        """Test token validation when no token exists."""
        auth = MecapyAuth("https://auth.example.com")
        assert not auth._is_token_valid()

    def test_is_token_valid_expired_token(self):
        """Test token validation with expired token."""
        auth = MecapyAuth("https://auth.example.com")
        auth._access_token = "token"
        auth._token_expires_at = datetime.now() - timedelta(minutes=1)

        assert not auth._is_token_valid()

    def test_is_token_valid_valid_token(self):
        """Test token validation with valid token."""
        auth = MecapyAuth("https://auth.example.com")
        auth._access_token = "token"
        auth._token_expires_at = datetime.now() + timedelta(hours=1)

        assert auth._is_token_valid()

    @pytest.mark.asyncio
    async def test_get_new_token_no_credentials(self):
        """Test getting new token without credentials."""
        auth = MecapyAuth("https://auth.example.com")

        with pytest.raises(AuthenticationError, match="Username and password are required"):
            await auth._get_new_token()

    @pytest.mark.asyncio
    async def test_get_new_token_success(self):
        """Test successful token retrieval."""
        auth = MecapyAuth("https://auth.example.com", username="testuser", password="testpass")

        token_response = {"access_token": "new_token", "refresh_token": "refresh_token", "expires_in": 300}

        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json = AsyncMock(return_value=token_response)

            mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_response)

            await auth._get_new_token()

            assert auth._access_token == "new_token"
            assert auth._refresh_token == "refresh_token"
            assert auth._token_expires_at is not None

    @pytest.mark.asyncio
    async def test_get_new_token_invalid_credentials(self):
        """Test token retrieval with invalid credentials."""
        auth = MecapyAuth("https://auth.example.com", username="baduser", password="badpass")

        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 401

            mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_response)

            with pytest.raises(AuthenticationError, match="Invalid username or password"):
                await auth._get_new_token()

    @pytest.mark.asyncio
    async def test_get_new_token_network_error(self):
        """Test token retrieval with network error."""
        auth = MecapyAuth("https://auth.example.com", username="testuser", password="testpass")

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                side_effect=httpx.RequestError("Network error")
            )

            with pytest.raises(NetworkError, match="Network error during authentication"):
                await auth._get_new_token()

    @pytest.mark.asyncio
    async def test_get_access_token_valid_token(self):
        """Test getting access token when current token is valid."""
        auth = MecapyAuth("https://auth.example.com")
        auth._access_token = "valid_token"
        auth._token_expires_at = datetime.now() + timedelta(hours=1)

        token = await auth.get_access_token()
        assert token == "valid_token"

    def test_logout(self):
        """Test logout functionality."""
        auth = MecapyAuth("https://auth.example.com")
        auth._access_token = "token"
        auth._refresh_token = "refresh"
        auth._token_expires_at = datetime.now()

        auth.logout()

        assert auth._access_token is None
        assert auth._refresh_token is None
        assert auth._token_expires_at is None

    def test_from_env_default_url(self):
        """Test from env with default MECAPY_KEYCLOAK_URL."""
        with patch.dict("os.environ", {}, clear=True):
            auth = MecapyAuth()
            assert auth.keycloak_url == "https://auth.mecapy.com"

    def test_from_env_success(self):
        """Test successful from env creation."""
        env_vars = {
            "MECAPY_KEYCLOAK_URL": "https://auth.example.com",
            "MECAPY_REALM": "custom-realm",
            "MECAPY_CLIENT_ID": "custom-client",
            "MECAPY_USERNAME": "testuser",
            "MECAPY_PASSWORD": "testpass",
        }

        with patch.dict("os.environ", env_vars):
            auth = MecapyAuth()

            assert auth.keycloak_url == "https://auth.example.com"
            assert auth.realm == "custom-realm"
            assert auth.client_id == "custom-client"
            assert auth.username == "testuser"
            assert auth.password == "testpass"

    @pytest.mark.asyncio
    async def test_get_access_token_with_refresh(self):
        """Test get_access_token when refresh token is available."""
        auth = MecapyAuth("https://auth.example.com", realm="test", client_id="test")
        auth._access_token = None  # No current token
        auth._refresh_token = "refresh_token"

        # Mock the refresh token method
        with patch.object(auth, "_refresh_access_token") as mock_refresh:
            mock_refresh.return_value = None
            auth._access_token = "new_token"  # Set after refresh

            token = await auth.get_access_token()
            assert token == "new_token"
            mock_refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_access_token_refresh_fails_fallback_to_new_token(self):
        """Test get_access_token when refresh fails and falls back to new token."""
        auth = MecapyAuth("https://auth.example.com", realm="test", client_id="test")
        auth._access_token = None
        auth._refresh_token = "invalid_refresh"

        with (
            patch.object(auth, "_refresh_access_token") as mock_refresh,
            patch.object(auth, "_get_new_token") as mock_new,
        ):
            mock_refresh.side_effect = AuthenticationError("Refresh failed")
            mock_new.return_value = None
            auth._access_token = "new_token"  # Set after getting new token

            token = await auth.get_access_token()
            assert token == "new_token"
            mock_refresh.assert_called_once()
            mock_new.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_new_token_non_200_status(self):
        """Test _get_new_token with non-200 status code."""
        auth = MecapyAuth("https://auth.example.com", realm="test", client_id="test")
        auth.set_credentials("user", "pass")

        mock_response = AsyncMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"

        with patch("httpx.AsyncClient.post", return_value=mock_response):
            with pytest.raises(AuthenticationError, match="Authentication failed: Internal Server Error"):
                await auth._get_new_token()

    @pytest.mark.asyncio
    async def test_refresh_access_token_no_refresh_token(self):
        """Test _refresh_access_token when no refresh token is available."""
        auth = MecapyAuth("https://auth.example.com", realm="test", client_id="test")
        auth._refresh_token = None

        with pytest.raises(AuthenticationError, match="No refresh token available"):
            await auth._refresh_access_token()

    @pytest.mark.asyncio
    async def test_refresh_access_token_401_error(self):
        """Test _refresh_access_token with 401 error."""
        auth = MecapyAuth("https://auth.example.com", realm="test", client_id="test")
        auth._refresh_token = "expired_refresh"

        mock_response = AsyncMock()
        mock_response.status_code = 401

        with patch("httpx.AsyncClient.post", return_value=mock_response):
            with pytest.raises(AuthenticationError, match="Refresh token expired or invalid"):
                await auth._refresh_access_token()

    @pytest.mark.asyncio
    async def test_refresh_access_token_non_200_status(self):
        """Test _refresh_access_token with non-200 status code."""
        auth = MecapyAuth("https://auth.example.com", realm="test", client_id="test")
        auth._refresh_token = "valid_refresh"

        mock_response = AsyncMock()
        mock_response.status_code = 500
        mock_response.text = "Server Error"

        with patch("httpx.AsyncClient.post", return_value=mock_response):
            with pytest.raises(AuthenticationError, match="Token refresh failed: Server Error"):
                await auth._refresh_access_token()

    @pytest.mark.asyncio
    async def test_refresh_access_token_network_error(self):
        """Test _refresh_access_token with network error."""
        auth = MecapyAuth("https://auth.example.com", realm="test", client_id="test")
        auth._refresh_token = "valid_refresh"

        with patch("httpx.AsyncClient.post", side_effect=httpx.RequestError("Network error")):
            with pytest.raises(NetworkError, match="Network error during token refresh"):
                await auth._refresh_access_token()
