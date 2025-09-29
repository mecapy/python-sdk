"""Tests for authentication module."""

import os
from unittest.mock import Mock, patch

import pytest
import requests

from mecapy.auth import (
    Auth,
    DefaultAuth,
    OAuth2Auth,
    OAuthCallbackHandler,
    ServiceAccountAuth,
    TokenAuth,
)
from mecapy.exceptions import NoAccessTokenError, NoFreePortError


@pytest.mark.unit
class TestOAuthCallbackHandler:
    """Test OAuthCallbackHandler class."""

    def test_do_get_with_code(self):
        """Test GET request with authorization code."""
        # Create a mock handler without calling __init__
        handler = OAuthCallbackHandler.__new__(OAuthCallbackHandler)
        handler.server = Mock()
        handler.path = "/callback?code=test_auth_code&state=test_state"
        handler.send_response = Mock()
        handler.end_headers = Mock()
        handler.wfile = Mock()

        handler.do_GET()

        assert handler.server.auth_code == "test_auth_code"
        handler.send_response.assert_called_once_with(200)
        handler.wfile.write.assert_called_once_with(
            b"<h1>Authentication successful!</h1><p>You can close this window.</p>"
        )

    def test_do_get_without_code(self):
        """Test GET request without authorization code."""
        # Create a mock handler without calling __init__
        handler = OAuthCallbackHandler.__new__(OAuthCallbackHandler)
        handler.server = Mock(spec=[])  # Empty spec to avoid auto-added attributes
        handler.path = "/callback?error=access_denied"
        handler.send_response = Mock()
        handler.end_headers = Mock()
        handler.wfile = Mock()

        handler.do_GET()

        # Check that auth_code was not set on the server
        assert not hasattr(handler.server, "auth_code") or getattr(handler.server, "auth_code", None) is None
        handler.send_response.assert_called_once_with(400)
        handler.wfile.write.assert_called_once_with(b"<h1>Error: code not found</h1>")


@pytest.mark.unit
class TestTokenAuth:
    """Test TokenAuth class."""

    def test_init_success(self):
        """Test successful initialization."""
        auth = TokenAuth("test-token")
        assert auth.token == "test-token"

    def test_init_strips_whitespace(self):
        """Test initialization strips whitespace."""
        auth = TokenAuth("  test-token  ")
        assert auth.token == "test-token"

    def test_init_empty_token(self):
        """Test initialization with empty token."""
        with pytest.raises(ValueError, match="Token cannot be empty"):
            TokenAuth("")

    def test_get_access_token(self):
        """Test getting access token."""
        auth = TokenAuth("test-token")
        assert auth.get_access_token() == "test-token"

    def test_call_method(self):
        """Test __call__ method adds auth header."""
        auth = TokenAuth("test-token")
        request = Mock()
        request.headers = {}

        result = auth(request)

        assert request.headers["Authorization"] == "Bearer test-token"
        assert result == request


@pytest.mark.unit
class TestServiceAccountAuth:
    """Test ServiceAccountAuth class."""

    def test_init_success(self):
        """Test successful initialization."""
        auth = ServiceAccountAuth("client-id", "client-secret")
        assert auth.client_id == "client-id"
        assert auth.client_secret == "client-secret"

    def test_get_token_endpoint(self):
        """Test token endpoint construction."""
        auth = ServiceAccountAuth("client-id", "client-secret")
        endpoint = auth._get_token_endpoint()
        assert "protocol/openid-connect/token" in endpoint

    @patch("requests.post")
    def test_fetch_token_success(self, mock_post):
        """Test successful token fetch."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "access_token": "test-access-token",
            "expires_in": 3600,
            "token_type": "Bearer",
        }
        mock_post.return_value = mock_response

        auth = ServiceAccountAuth("client-id", "client-secret")
        token = auth._fetch_token()

        assert token["access_token"] == "test-access-token"
        assert token["expires_in"] == 3600

    @patch("requests.post")
    def test_get_access_token_success(self, mock_post):
        """Test successful access token retrieval."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "access_token": "test-access-token",
            "expires_in": 3600,
            "token_type": "Bearer",
        }
        mock_post.return_value = mock_response

        auth = ServiceAccountAuth("client-id", "client-secret")
        token = auth.get_access_token()

        assert token == "test-access-token"

    def test_get_access_token_no_token_in_response(self):
        """Test access token retrieval with no token in response."""
        auth = ServiceAccountAuth("client-id", "client-secret")
        auth._token_cache = {"expires_in": 3600}  # No access_token

        with pytest.raises(NoAccessTokenError):
            auth.get_access_token()

    @patch("requests.post")
    def test_get_access_token_no_cache(self, mock_post):
        """Test access token retrieval with no cached token."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "access_token": "test-access-token",
            "expires_in": 3600,
            "token_type": "Bearer",
        }
        mock_post.return_value = mock_response

        auth = ServiceAccountAuth("client-id", "client-secret")
        auth._token_cache = None

        token = auth.get_access_token()
        assert token == "test-access-token"

    def test_is_token_valid_no_cache(self):
        """Test token validation with no cache."""
        auth = ServiceAccountAuth("client-id", "client-secret")
        auth._token_cache = None
        assert not auth._is_token_valid()

    def test_is_token_valid_expired(self):
        """Test token validation with expired token."""
        auth = ServiceAccountAuth("client-id", "client-secret")
        auth._token_cache = {"access_token": "token", "expires_in": 30}  # Less than 60s
        assert not auth._is_token_valid()

    def test_is_token_valid_valid(self):
        """Test token validation with valid token."""
        auth = ServiceAccountAuth("client-id", "client-secret")
        auth._token_cache = {"access_token": "token", "expires_in": 3600}  # More than 60s
        assert auth._is_token_valid()

    @patch("requests.post")
    def test_fetch_token_http_error(self, mock_post):
        """Test token fetch with HTTP error."""
        mock_post.side_effect = requests.RequestException("Network error")

        auth = ServiceAccountAuth("client-id", "client-secret")

        with pytest.raises(requests.RequestException):
            auth._fetch_token()


@pytest.mark.unit
class TestOAuth2Auth:
    """Test OAuth2Auth class."""

    @patch("mecapy.auth.requests.get")
    def test_fetch_oidc_config(self, mock_get):
        """Test OIDC configuration fetch."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "authorization_endpoint": "https://auth.example.com/auth",
            "token_endpoint": "https://auth.example.com/token",
        }
        mock_get.return_value = mock_response

        auth = OAuth2Auth()
        config = auth.fetch_oidc_config()

        assert "authorization_endpoint" in config
        assert "token_endpoint" in config

    @patch.object(OAuth2Auth, "is_port_free")
    def test_set_port_success(self, mock_is_port_free):
        """Test successful port selection."""
        mock_is_port_free.side_effect = [False, True, False]  # Second port is free

        auth = OAuth2Auth.__new__(OAuth2Auth)  # Don't call __init__
        port = auth.set_port(8085, 8086, 8087)

        assert port == 8086

    @patch.object(OAuth2Auth, "is_port_free")
    def test_set_port_no_free_port(self, mock_is_port_free):
        """Test port selection when no ports are free."""
        mock_is_port_free.return_value = False

        auth = OAuth2Auth.__new__(OAuth2Auth)  # Don't call __init__
        with pytest.raises(NoFreePortError):
            auth.set_port(8085, 8086, 8087)

    def test_is_port_free_success(self):
        """Test port availability check."""
        # This test might be flaky depending on system state
        # Using a very high port number to reduce conflicts
        result = OAuth2Auth.is_port_free(65432)
        assert isinstance(result, bool)

    def test_get_access_token_success(self):
        """Test successful access token retrieval."""
        auth = OAuth2Auth.__new__(OAuth2Auth)
        auth.get_token = Mock(return_value={"access_token": "test-token"})

        token = auth.get_access_token()

        assert token == "test-token"

    def test_get_access_token_no_token(self):
        """Test access token retrieval with no token."""
        auth = OAuth2Auth.__new__(OAuth2Auth)
        auth.get_token = Mock(return_value={})

        with pytest.raises(NoAccessTokenError):
            auth.get_access_token()

    @patch("mecapy.auth.requests.get")
    def test_fetch_oidc_config_http_error(self, mock_get):
        """Test OIDC configuration fetch with HTTP error."""
        mock_get.side_effect = requests.RequestException("Network error")

        with pytest.raises(requests.RequestException):
            OAuth2Auth().fetch_oidc_config()

    def test_oauth2_constants(self):
        """Test OAuth2Auth constants."""
        assert OAuth2Auth.LOCALHOST == "127.0.0.1"
        assert OAuth2Auth.SOCKET_TIMEOUT == 0.5
        assert OAuth2Auth.CODE_VERIFIER_LENGTH == 48
        assert OAuth2Auth.CODE_CHALLENGE_METHOD == "S256"

    @patch("keyring.get_password")
    def test_retrieve_stored_token_success(self, mock_get_password):
        """Test successful token retrieval from keyring."""
        mock_get_password.return_value = '{"access_token": "stored-token"}'

        auth = OAuth2Auth.__new__(OAuth2Auth)
        token = auth._retrieve_stored_token()

        assert token == {"access_token": "stored-token"}

    @patch("keyring.get_password")
    def test_retrieve_stored_token_none(self, mock_get_password):
        """Test token retrieval when no token stored."""
        mock_get_password.return_value = None

        auth = OAuth2Auth.__new__(OAuth2Auth)
        token = auth._retrieve_stored_token()

        assert token is None

    @patch("keyring.get_password")
    @patch("mecapy.auth.json.loads", side_effect=Exception("JSON error"))
    def test_retrieve_stored_token_invalid_json(self, mock_json_loads, mock_get_password):
        """Test token retrieval with invalid JSON."""
        mock_get_password.return_value = "invalid-json"

        auth = OAuth2Auth.__new__(OAuth2Auth)
        token = auth._retrieve_stored_token()
        assert token is None

    @patch("keyring.set_password")
    def test_store_token(self, mock_set_password):
        """Test token storage."""
        auth = OAuth2Auth.__new__(OAuth2Auth)
        token_data = {"access_token": "test-token"}

        auth._store_token(token_data)

        mock_set_password.assert_called_once()


@pytest.mark.unit
class TestDefaultAuth:
    """Test DefaultAuth class."""

    def test_get_auth_strategy_with_env_token(self):
        """Test strategy selection with environment token."""
        with patch.dict(os.environ, {"MECAPY_TOKEN": "env-token"}):
            auth = DefaultAuth()
            strategy = auth._get_auth_strategy()

            assert isinstance(strategy, TokenAuth)
            assert strategy.token == "env-token"

    @patch("mecapy.auth.OAuth2Auth")
    def test_get_auth_strategy_with_stored_token(self, mock_oauth2_class):
        """Test strategy selection with stored OAuth2 token."""
        mock_oauth2 = Mock()
        mock_oauth2._retrieve_stored_token.return_value = {"access_token": "stored-token"}
        mock_oauth2_class.return_value = mock_oauth2

        with patch.dict(os.environ, {}, clear=True):
            auth = DefaultAuth()
            strategy = auth._get_auth_strategy()

            assert strategy == mock_oauth2

    @patch("mecapy.auth.OAuth2Auth")
    def test_get_auth_strategy_fallback_to_oauth2(self, mock_oauth2_class):
        """Test strategy selection falls back to OAuth2."""
        mock_oauth2 = Mock()
        mock_oauth2._retrieve_stored_token.return_value = None
        mock_oauth2_class.return_value = mock_oauth2

        with patch.dict(os.environ, {}, clear=True):
            auth = DefaultAuth()
            strategy = auth._get_auth_strategy()

            assert strategy == mock_oauth2

    def test_get_access_token(self):
        """Test access token retrieval."""
        auth = DefaultAuth()
        mock_strategy = Mock()
        mock_strategy.get_access_token.return_value = "strategy-token"
        auth._auth_strategy = mock_strategy

        token = auth.get_access_token()

        assert token == "strategy-token"

    @patch("mecapy.auth.OAuth2Auth")
    def test_get_auth_strategy_oauth_failed_fallback(self, mock_oauth2_class):
        """Test strategy fallback when OAuth2 also fails."""
        mock_oauth2 = Mock()
        mock_oauth2._retrieve_stored_token.side_effect = Exception("OAuth2 failed")
        mock_oauth2_class.return_value = mock_oauth2

        with patch.dict(os.environ, {}, clear=True):
            auth = DefaultAuth()
            strategy = auth._get_auth_strategy()
            # Should still return the OAuth2 instance despite failure
            assert strategy == mock_oauth2

    def test_call_method(self):
        """Test __call__ method delegates to strategy."""
        auth = DefaultAuth()
        mock_strategy = Mock()
        auth._auth_strategy = mock_strategy

        request = Mock()
        result = auth(request)

        mock_strategy.assert_called_once_with(request)
        assert result == mock_strategy.return_value


@pytest.mark.unit
class TestAuth:
    """Test Auth namespace class."""

    def test_token_creation(self):
        """Test Token auth creation."""
        auth = Auth.Token("test-token")
        assert isinstance(auth, TokenAuth)
        assert auth.token == "test-token"

    def test_service_account_creation(self):
        """Test ServiceAccount auth creation."""
        auth = Auth.ServiceAccount("client-id", "client-secret")
        assert isinstance(auth, ServiceAccountAuth)
        assert auth.client_id == "client-id"
        assert auth.client_secret == "client-secret"

    @patch("mecapy.auth.requests.get")
    def test_oauth2_creation(self, mock_get):
        """Test OAuth2 auth creation."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "authorization_endpoint": "https://auth.example.com/auth",
            "token_endpoint": "https://auth.example.com/token",
        }
        mock_get.return_value = mock_response

        auth = Auth.OAuth2()
        assert isinstance(auth, OAuth2Auth)

    def test_default_creation(self):
        """Test Default auth creation."""
        auth = Auth.Default()
        assert isinstance(auth, DefaultAuth)
