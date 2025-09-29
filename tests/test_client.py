"""Tests for MecaPy client."""

from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import requests

from mecapy import MecaPyClient
from mecapy.auth import Auth, DefaultAuth
from mecapy.exceptions import (
    AuthenticationError,
    NetworkError,
    NotFoundError,
    ServerError,
    ValidationError,
)
from mecapy.models import (
    APIResponse,
    UploadResponse,
    UserInfo,
)


@pytest.mark.unit
class TestMecaPyClient:
    """Test MecaPyClient class."""

    def test_init(self):
        """Test client initialization."""
        client = MecaPyClient(api_url="https://api.example.com/", timeout=15.0)

        assert client.api_url == "https://api.example.com"
        assert isinstance(client.auth, DefaultAuth)
        assert client.timeout == 15.0

    def test_init_with_auth(self):
        """Test client initialization with auth."""
        auth = Auth.Token("test-token")
        client = MecaPyClient(api_url="https://api.example.com/", auth=auth, timeout=15.0)

        assert client.api_url == "https://api.example.com"
        assert client.auth == auth
        assert client.timeout == 15.0

    def test_context_manager(self):
        """Test client as context manager (optional)."""
        with MecaPyClient("https://api.example.com") as client:
            assert isinstance(client, MecaPyClient)

    def test_direct_usage(self):
        """Test client direct usage without context manager."""
        client = MecaPyClient("https://api.example.com")
        assert isinstance(client, MecaPyClient)
        # Should work without needing explicit close
        assert client.api_url == "https://api.example.com"

    def test_from_env_default_urls(self):
        """Test from_env with default URLs."""
        client = MecaPyClient.from_env()
        # Default from config might be localhost in test env
        assert isinstance(client.api_url, str)

    def test_from_env_success(self):
        """Test from_env creation."""
        client = MecaPyClient.from_env(api_url="https://test.example.com", timeout=20.0)
        assert client.api_url == "https://test.example.com"
        assert client.timeout == 20.0

    def test_from_env_custom_urls(self):
        """Test from_env with custom URLs."""
        client = MecaPyClient.from_env(api_url="https://custom.api.com", timeout=25.0)
        assert client.api_url == "https://custom.api.com"
        assert client.timeout == 25.0

    def test_from_token(self):
        """Test from_token creation."""
        client = MecaPyClient.from_token("test-token", api_url="https://api.example.com")
        assert client.api_url == "https://api.example.com"
        assert hasattr(client.auth, "token")

    def test_make_request_authentication_error(self, client):
        """Test request with authentication error."""
        with patch.object(client, "_session") as mock_session:
            mock_response = Mock()
            mock_response.status_code = 401
            mock_session.send.return_value = mock_response

            with pytest.raises(AuthenticationError, match="Authentication failed"):
                client._make_request("GET", "/test")

    def test_make_request_not_found(self, client):
        """Test request with 404 error."""
        with patch.object(client, "_session") as mock_session:
            mock_response = Mock()
            mock_response.status_code = 404
            mock_session.send.return_value = mock_response

            with pytest.raises(NotFoundError, match="Resource not found"):
                client._make_request("GET", "/test")

    def test_make_request_validation_error(self, client):
        """Test request with validation error."""
        with patch.object(client, "_session") as mock_session:
            mock_response = Mock()
            mock_response.status_code = 422
            mock_response.json.return_value = {"detail": "Validation failed"}
            mock_session.send.return_value = mock_response

            with pytest.raises(ValidationError, match="Request validation failed"):
                client._make_request("GET", "/test")

    def test_make_request_server_error(self, client):
        """Test request with server error."""
        with patch.object(client, "_session") as mock_session:
            mock_response = Mock()
            mock_response.status_code = 500
            mock_response.text = "Internal server error"
            mock_session.send.return_value = mock_response

            with pytest.raises(ServerError, match="Server error"):
                client._make_request("GET", "/test")

    def test_make_request_network_error(self, client):
        """Test request with network error."""
        with patch.object(client, "_session") as mock_session:
            mock_session.send.side_effect = requests.RequestException("Connection failed")

            with pytest.raises(NetworkError, match="Network error"):
                client._make_request("GET", "/test")

    def test_get_root(self, client_no_auth):
        """Test getting API root."""
        with patch.object(client_no_auth, "_session") as mock_session:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "message": "Welcome to MecaPy API",
                "status": "active",
                "version": "1.0.0",
            }
            mock_session.send.return_value = mock_response

            result = client_no_auth.get_root()

            assert isinstance(result, APIResponse)
            assert result.version == "1.0.0"
            assert result.message == "Welcome to MecaPy API"

    def test_health_check(self, client_no_auth):
        """Test health check endpoint."""
        with patch.object(client_no_auth, "_session") as mock_session:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"status": "ok"}
            mock_session.send.return_value = mock_response

            result = client_no_auth.health_check()

            assert result == {"status": "ok"}

    def test_get_current_user(self, client):
        """Test getting current user."""
        with patch.object(client, "_session") as mock_session:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "preferred_username": "testuser",
                "email": "test@example.com",
                "given_name": "Test",
                "family_name": "User",
                "roles": ["user"],
            }
            mock_session.send.return_value = mock_response

            result = client.get_current_user()

            assert isinstance(result, UserInfo)
            assert result.preferred_username == "testuser"
            assert result.email == "test@example.com"

    def test_json_with_non_awaitable_response(self, client):
        """Test _json method with non-awaitable response."""
        mock_response = Mock()
        mock_response.json.return_value = {"key": "value"}

        result = client._json(mock_response)

        assert result == {"key": "value"}

    def test_upload_archive_string_path(self, client):
        """Test upload with string path."""
        test_file = Path("test_archive.zip")
        test_file.write_bytes(b"fake zip content")

        try:
            with patch.object(client, "_session") as mock_session:
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.json.return_value = {
                    "message": "Upload successful",
                    "original_filename": "test_archive.zip",
                    "uploaded_filename": "uploaded_test_archive.zip",
                    "md5": "fake_md5",
                    "size": 16,
                }
                mock_session.send.return_value = mock_response

                result = client.upload_archive(str(test_file))

                assert isinstance(result, UploadResponse)
                assert result.original_filename == "test_archive.zip"
        finally:
            test_file.unlink(missing_ok=True)

    def test_upload_archive_path_object(self, client):
        """Test upload with Path object."""
        test_file = Path("test_archive.zip")
        test_file.write_bytes(b"fake zip content")

        try:
            with patch.object(client, "_session") as mock_session:
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.json.return_value = {
                    "message": "Upload successful",
                    "original_filename": "test_archive.zip",
                    "uploaded_filename": "uploaded_test_archive.zip",
                    "md5": "fake_md5",
                    "size": 16,
                }
                mock_session.send.return_value = mock_response

                result = client.upload_archive(test_file)

                assert isinstance(result, UploadResponse)
                assert result.original_filename == "test_archive.zip"
        finally:
            test_file.unlink(missing_ok=True)

    def test_upload_archive_file_not_found(self, client):
        """Test upload with non-existent file."""
        with pytest.raises(ValidationError, match="File not found"):
            client.upload_archive("nonexistent_file.zip")

    def test_upload_archive_invalid_extension(self, client):
        """Test upload with invalid file extension."""
        test_file = Path("test_file.txt")
        test_file.write_text("test content")

        try:
            with pytest.raises(ValidationError, match="Only ZIP files are allowed"):
                client.upload_archive(test_file)
        finally:
            test_file.unlink(missing_ok=True)

    def test_upload_archive_file_object(self, client):
        """Test upload with file-like object."""
        from io import BytesIO

        file_obj = BytesIO(b"fake zip content")

        with patch.object(client, "_session") as mock_session:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "message": "Upload successful",
                "original_filename": "test.zip",
                "uploaded_filename": "uploaded_test.zip",
                "md5": "fake_md5",
                "size": 16,
            }
            mock_session.send.return_value = mock_response

            result = client.upload_archive(file_obj, filename="test.zip")

            assert isinstance(result, UploadResponse)
            assert result.original_filename == "test.zip"

    def test_upload_archive_file_object_no_filename(self, client):
        """Test upload with file-like object but no filename."""
        from io import BytesIO

        file_obj = BytesIO(b"fake zip content")

        with pytest.raises(ValidationError, match="filename is required"):
            client.upload_archive(file_obj)

    def test_make_request_403_error(self, client):
        """Test request with 403 forbidden error."""
        with patch.object(client, "_session") as mock_session:
            mock_response = Mock()
            mock_response.status_code = 403
            mock_session.send.return_value = mock_response

            with pytest.raises(AuthenticationError, match="Access forbidden"):
                client._make_request("GET", "/test")

    def test_make_request_4xx_error(self, client):
        """Test request with 4xx client error."""
        with patch.object(client, "_session") as mock_session:
            mock_response = Mock()
            mock_response.status_code = 400
            mock_response.text = "Bad request"
            mock_session.send.return_value = mock_response

            with pytest.raises(ValidationError, match="Client error"):
                client._make_request("GET", "/test")

    def test_test_protected_route(self, client):
        """Test protected route."""
        with patch.object(client, "_session") as mock_session:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "message": "Protected route accessed",
                "user_info": {"preferred_username": "testuser"},
                "endpoint": "/auth/protected",
            }
            mock_session.send.return_value = mock_response

            result = client.test_protected_route()

            assert result.message == "Protected route accessed"

    def test_test_admin_route(self, client):
        """Test admin route."""
        with patch.object(client, "_session") as mock_session:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "message": "Admin route accessed",
                "admin_access": True,
                "endpoint": "/auth/admin",
            }
            mock_session.send.return_value = mock_response

            result = client.test_admin_route()

            assert result.message == "Admin route accessed"
            assert result.admin_access is True

    def test_del_method(self):
        """Test __del__ method."""
        client = MecaPyClient(api_url="https://api.example.com")
        with patch.object(client, "close") as mock_close:
            client.__del__()
            mock_close.assert_called_once()

    def test_del_method_with_exception(self):
        """Test __del__ method when close raises exception."""
        client = MecaPyClient(api_url="https://api.example.com")
        with patch.object(client, "close", side_effect=Exception("Close error")):
            # Should not raise exception
            client.__del__()

    def test_normalize_username_field_with_username(self, client):
        """Test username field normalization."""
        data = {"username": "testuser", "email": "test@example.com"}
        result = client._normalize_username_field(data)
        assert result["preferred_username"] == "testuser"
        assert result["username"] == "testuser"

    def test_normalize_username_field_with_preferred_username(self, client):
        """Test username field normalization when preferred_username already exists."""
        data = {"preferred_username": "testuser", "email": "test@example.com"}
        result = client._normalize_username_field(data)
        assert result["preferred_username"] == "testuser"

    def test_normalize_username_field_non_dict(self, client):
        """Test username field normalization with non-dict input."""
        result = client._normalize_username_field("not a dict")
        assert result == "not a dict"

    def test_normalize_nested_user_info(self, client):
        """Test nested user_info normalization."""
        data = {"message": "Success", "user_info": {"username": "testuser", "email": "test@example.com"}}
        result = client._normalize_nested_user_info(data)
        assert result["user_info"]["preferred_username"] == "testuser"
        assert result["user_info"]["username"] == "testuser"

    def test_normalize_nested_user_info_no_user_info(self, client):
        """Test nested user_info normalization without user_info."""
        data = {"message": "Success"}
        result = client._normalize_nested_user_info(data)
        assert result == data

    def test_handle_authentication_error(self, client):
        """Test authentication error handling."""
        from mecapy.exceptions import AuthenticationError

        request = Mock()

        # Mock auth to raise exception
        client.auth = Mock()
        client.auth.side_effect = Exception("Auth failed")

        with pytest.raises(AuthenticationError, match="Failed to authenticate request"):
            client._handle_authentication(request)
