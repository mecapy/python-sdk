"""Tests for authentication module."""

import json
from unittest.mock import Mock, patch

import pytest

from mecapy.auth import MecapyAuth, OAuthCallbackHandler
from mecapy.exceptions import NoAccessTokenError, NoAuthCodeError, NoFreePortError


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
class TestMecapyAuth:
    """Test MecapyAuth class."""

    @patch("mecapy.auth.config")
    @patch.object(MecapyAuth, "fetch_oidc_config")
    @patch.object(MecapyAuth, "set_port")
    def test_init(self, mock_set_port, mock_fetch_oidc_config, mock_config):
        """Test MecapyAuth initialization."""
        mock_config.auth.client_id = "test-client"
        mock_config.auth.realm = "test-realm"
        mock_config.auth.issuer = "https://auth.example.com/realms/test-realm"
        mock_set_port.return_value = 8085
        mock_fetch_oidc_config.return_value = {
            "authorization_endpoint": "https://auth.example.com/auth",
            "token_endpoint": "https://auth.example.com/token",
        }

        auth = MecapyAuth()

        assert auth.client_id == "test-client"
        assert auth.realm == "test-realm"
        assert auth.issuer == "https://auth.example.com/realms/test-realm"
        assert auth.port == 8085
        assert auth.redirect_uri == "http://localhost:8085/callback"
        mock_fetch_oidc_config.assert_called_once()

    @patch("socket.socket")
    def test_is_port_free_available(self, mock_socket):
        """Test is_port_free when port is available."""
        mock_socket.return_value.__enter__.return_value.bind.return_value = None

        result = MecapyAuth.is_port_free(8080)

        assert result is True

    @patch("socket.socket")
    def test_is_port_free_occupied(self, mock_socket):
        """Test is_port_free when port is occupied."""
        mock_socket.return_value.__enter__.return_value.bind.side_effect = OSError()

        result = MecapyAuth.is_port_free(8080)

        assert result is False

    @patch.object(MecapyAuth, "is_port_free")
    def test_set_port_success(self, mock_is_port_free):
        """Test successful port setting."""
        mock_is_port_free.side_effect = [False, True, False]

        auth = MecapyAuth.__new__(MecapyAuth)  # Skip __init__
        result = auth.set_port(8080, 8081, 8082)

        assert result == 8081

    @patch.object(MecapyAuth, "is_port_free")
    def test_set_port_no_free_port(self, mock_is_port_free):
        """Test port setting when no port is free."""
        mock_is_port_free.return_value = False

        auth = MecapyAuth.__new__(MecapyAuth)  # Skip __init__

        with pytest.raises(NoFreePortError):
            auth.set_port(8080, 8081, 8082)

    @patch("requests.get")
    @patch("mecapy.auth.config")
    def test_fetch_oidc_config(self, mock_config, mock_get):
        """Test OIDC configuration fetching."""
        mock_config.auth.get_oidc_discovery_url.return_value = (
            "https://auth.example.com/.well-known/openid_configuration"
        )
        mock_response = Mock()
        mock_response.json.return_value = {"issuer": "https://auth.example.com"}
        mock_get.return_value = mock_response

        auth = MecapyAuth.__new__(MecapyAuth)  # Skip __init__
        result = auth.fetch_oidc_config()

        assert result == {"issuer": "https://auth.example.com"}
        mock_get.assert_called_once_with("https://auth.example.com/.well-known/openid_configuration", timeout=10)
        mock_response.raise_for_status.assert_called_once()

    @patch("http.server.HTTPServer")
    def test_waiting_for_code_success(self, mock_http_server):
        """Test successful authorization code waiting."""
        mock_server = Mock()
        mock_server.auth_code = "test_code"
        mock_http_server.return_value.__enter__.return_value = mock_server

        auth = MecapyAuth.__new__(MecapyAuth)  # Skip __init__
        auth.port = 8080

        result = auth.waiting_for_code()

        assert result == "test_code"

    @patch("http.server.HTTPServer")
    def test_waiting_for_code_failure(self, mock_http_server):
        """Test authorization code waiting failure."""
        mock_server = Mock()
        del mock_server.auth_code  # No auth_code attribute
        mock_http_server.return_value.__enter__.return_value = mock_server

        auth = MecapyAuth.__new__(MecapyAuth)  # Skip __init__
        auth.port = 8080

        with pytest.raises(NoAuthCodeError):
            auth.waiting_for_code()

    @patch("keyring.set_password")
    def test_store_token(self, mock_set_password):
        """Test token storage."""
        auth = MecapyAuth.__new__(MecapyAuth)  # Skip __init__
        token_data = {"access_token": "test_token", "refresh_token": "test_refresh"}

        auth._store_token(token_data)

        mock_set_password.assert_called_once_with("MecaPy", "token", json.dumps(token_data))

    @patch("keyring.get_password")
    def test_retrieve_stored_token_success(self, mock_get_password):
        """Test successful token retrieval."""
        token_data = {"access_token": "test_token"}
        mock_get_password.return_value = json.dumps(token_data)

        auth = MecapyAuth.__new__(MecapyAuth)  # Skip __init__
        result = auth._retrieve_stored_token()

        assert result == token_data
        mock_get_password.assert_called_once_with("MecaPy", "token")

    @patch("keyring.get_password")
    def test_retrieve_stored_token_none(self, mock_get_password):
        """Test token retrieval when no token exists."""
        mock_get_password.return_value = None

        auth = MecapyAuth.__new__(MecapyAuth)  # Skip __init__
        result = auth._retrieve_stored_token()

        assert result is None

    @patch("keyring.delete_password")
    def test_clear_stored_token(self, mock_delete_password):
        """Test token clearing."""
        auth = MecapyAuth.__new__(MecapyAuth)  # Skip __init__

        auth._clear_stored_token()

        mock_delete_password.assert_called_once_with("MecaPy", "token")

    @patch.object(MecapyAuth, "_retrieve_stored_token")
    @patch.object(MecapyAuth, "login")
    def test_get_token_with_stored_token(self, mock_login, mock_retrieve):
        """Test get_token with stored token."""
        token_data = {"access_token": "stored_token"}
        mock_retrieve.return_value = token_data

        auth = MecapyAuth.__new__(MecapyAuth)  # Skip __init__
        result = auth.get_token()

        assert result == token_data
        mock_login.assert_not_called()

    @patch.object(MecapyAuth, "_retrieve_stored_token")
    @patch.object(MecapyAuth, "login")
    def test_get_token_without_stored_token(self, mock_login, mock_retrieve):
        """Test get_token without stored token."""
        mock_retrieve.return_value = None
        new_token = {"access_token": "new_token"}
        mock_login.return_value = new_token

        auth = MecapyAuth.__new__(MecapyAuth)  # Skip __init__
        result = auth.get_token()

        assert result == new_token
        mock_login.assert_called_once()

    @patch.object(MecapyAuth, "get_token")
    @pytest.mark.asyncio
    async def test_get_access_token_success(self, mock_get_token):
        """Test successful access token retrieval."""
        mock_get_token.return_value = {"access_token": "test_token"}

        auth = MecapyAuth.__new__(MecapyAuth)  # Skip __init__
        result = await auth.get_access_token()

        assert result == "test_token"

    @patch.object(MecapyAuth, "get_token")
    @pytest.mark.asyncio
    async def test_get_access_token_no_token(self, mock_get_token):
        """Test access token retrieval with no access token."""
        mock_get_token.return_value = {"refresh_token": "refresh_only"}

        auth = MecapyAuth.__new__(MecapyAuth)  # Skip __init__

        with pytest.raises(NoAccessTokenError):
            await auth.get_access_token()

    @patch("webbrowser.open")
    @patch.object(MecapyAuth, "waiting_for_code")
    @patch.object(MecapyAuth, "_store_token")
    @patch.object(MecapyAuth, "_create_oauth_client")
    def test_login_success(self, mock_create_client, mock_store_token, mock_waiting_for_code, mock_webbrowser):
        """Test successful login."""
        # Setup mocks
        mock_client = Mock()
        mock_client.create_authorization_url.return_value = ("https://auth.url", "state")
        mock_client.fetch_token.return_value = {"access_token": "new_token"}
        mock_create_client.return_value = mock_client
        mock_waiting_for_code.return_value = "auth_code"

        auth = MecapyAuth.__new__(MecapyAuth)  # Skip __init__
        auth.authorization_endpoint = "https://auth.example.com/auth"
        auth.token_endpoint = "https://auth.example.com/token"

        result = auth.login()

        assert result == {"access_token": "new_token"}
        mock_webbrowser.assert_called_once()
        mock_store_token.assert_called_once_with({"access_token": "new_token"})

    @patch.object(MecapyAuth, "get_session")
    @patch.object(MecapyAuth, "_clear_stored_token")
    def test_logout(self, mock_clear_stored_token, mock_get_session):
        """Test logout functionality."""
        mock_session = Mock()
        mock_session.token = {"access_token": "token1", "refresh_token": "token2"}
        mock_get_session.return_value = mock_session

        auth = MecapyAuth.__new__(MecapyAuth)  # Skip __init__
        auth.token_endpoint = "https://auth.example.com/token"

        auth.logout()

        assert mock_session.revoke_token.call_count == 2
        mock_clear_stored_token.assert_called_once()

    @patch.object(MecapyAuth, "get_token")
    @patch.object(MecapyAuth, "_create_oauth_client")
    def test_get_session_valid_token(self, mock_create_client, mock_get_token):
        """Test get_session with valid token."""
        token_data = {"access_token": "valid_token"}
        mock_get_token.return_value = token_data
        mock_session = Mock()
        mock_create_client.return_value = mock_session

        auth = MecapyAuth.__new__(MecapyAuth)  # Skip __init__
        result = auth.get_session()

        assert result == mock_session
        mock_session.ensure_active_token.assert_called_once()

    @patch.object(MecapyAuth, "get_token")
    @patch.object(MecapyAuth, "login")
    @patch.object(MecapyAuth, "_create_oauth_client")
    def test_get_session_expired_token(self, mock_create_client, mock_login, mock_get_token):
        """Test get_session with expired token requiring re-login."""
        # First call returns expired token, second call returns new token
        mock_get_token.return_value = {"access_token": "expired_token"}
        new_token = {"access_token": "new_token"}
        mock_login.return_value = new_token

        mock_session_expired = Mock()
        mock_session_expired.ensure_active_token.side_effect = Exception("Token expired")
        mock_session_new = Mock()
        mock_create_client.side_effect = [mock_session_expired, mock_session_new]

        auth = MecapyAuth.__new__(MecapyAuth)  # Skip __init__
        result = auth.get_session()

        assert result == mock_session_new
        mock_login.assert_called_once()

    def test_create_oauth_client_with_token(self):
        """Test _create_oauth_client with token."""
        auth = MecapyAuth.__new__(MecapyAuth)  # Skip __init__
        auth.client_id = "test-client"
        auth.redirect_uri = "http://localhost:8080/callback"
        auth.token_endpoint = "https://auth.example.com/token"

        token_data = {"access_token": "test_token"}

        with patch("mecapy.auth.OAuth2Session") as mock_oauth_session:
            result = auth._create_oauth_client(token=token_data)

            mock_oauth_session.assert_called_once_with(
                client_id="test-client",
                redirect_uri="http://localhost:8080/callback",
                token_endpoint="https://auth.example.com/token",
                code_challenge_method="S256",
                token=token_data,
            )
            assert result == mock_oauth_session.return_value

    def test_create_oauth_client_without_token(self):
        """Test _create_oauth_client without token."""
        auth = MecapyAuth.__new__(MecapyAuth)  # Skip __init__
        auth.client_id = "test-client"
        auth.redirect_uri = "http://localhost:8080/callback"
        auth.token_endpoint = "https://auth.example.com/token"

        with patch("mecapy.auth.OAuth2Session") as mock_oauth_session:
            result = auth._create_oauth_client()

            mock_oauth_session.assert_called_once_with(
                client_id="test-client",
                redirect_uri="http://localhost:8080/callback",
                token_endpoint="https://auth.example.com/token",
                code_challenge_method="S256",
                token=None,
            )
            assert result == mock_oauth_session.return_value
