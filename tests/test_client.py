"""Tests for MecaPy client."""

from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from mecapy import MecaPyClient
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

    @patch("mecapy.client.MecapyAuth")
    def test_init(self, mock_auth_class):
        """Test client initialization."""
        mock_auth = Mock()
        mock_auth_class.return_value = mock_auth

        client = MecaPyClient(api_url="https://api.example.com/", timeout=15.0)

        assert client.api_url == "https://api.example.com"
        assert client.auth == mock_auth
        assert client.timeout == 15.0

    @pytest.mark.asyncio
    @patch("mecapy.client.MecapyAuth")
    async def test_context_manager(self, mock_auth_class):
        """Test client as async context manager."""
        mock_auth = Mock()
        mock_auth_class.return_value = mock_auth

        async with MecaPyClient("https://api.example.com") as client:
            assert isinstance(client, MecaPyClient)

    @pytest.mark.asyncio
    async def test_make_request_authentication_error(self, client):
        """Test request with authentication error."""
        with patch.object(client, "_client") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 401
            mock_client.request = AsyncMock(return_value=mock_response)

            with pytest.raises(AuthenticationError, match="Authentication failed"):
                await client._make_request("GET", "/test")

    @pytest.mark.asyncio
    async def test_make_request_not_found(self, client):
        """Test request with 404 error."""
        with patch.object(client, "_client") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 404
            mock_client.request = AsyncMock(return_value=mock_response)

            with pytest.raises(NotFoundError, match="Resource not found"):
                await client._make_request("GET", "/test")

    @pytest.mark.asyncio
    async def test_make_request_validation_error(self, client):
        """Test request with validation error."""
        with patch.object(client, "_client") as mock_client:
            mock_response = Mock()
            mock_response.status_code = 422
            mock_response.json = Mock(return_value={"detail": "Validation failed"})
            mock_client.request = AsyncMock(return_value=mock_response)

            with pytest.raises(ValidationError, match="Request validation failed"):
                await client._make_request("GET", "/test")

    @pytest.mark.asyncio
    async def test_make_request_server_error(self, client):
        """Test request with server error."""
        with patch.object(client, "_client") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 500
            mock_response.text = "Internal server error"
            mock_client.request = AsyncMock(return_value=mock_response)

            with pytest.raises(ServerError, match="Server error"):
                await client._make_request("GET", "/test")

    @pytest.mark.asyncio
    async def test_make_request_network_error(self, client):
        """Test request with network error."""
        with patch.object(client, "_client") as mock_client:
            mock_client.request = AsyncMock(side_effect=httpx.RequestError("Connection failed"))

            with pytest.raises(NetworkError, match="Network error"):
                await client._make_request("GET", "/test")

    @pytest.mark.asyncio
    async def test_get_root(self, client_no_auth):
        """Test get_root method."""
        response_data = {"message": "Welcome to API", "status": "running", "version": "1.0.0"}

        with patch.object(client_no_auth, "_client") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json = AsyncMock(return_value=response_data)
            mock_client.request = AsyncMock(return_value=mock_response)

            result = await client_no_auth.get_root()

            assert isinstance(result, APIResponse)
            assert result.message == "Welcome to API"
            assert result.status == "running"
            assert result.version == "1.0.0"

    @pytest.mark.asyncio
    async def test_health_check(self, client_no_auth):
        """Test health_check method."""
        response_data = {"status": "ok"}

        with patch.object(client_no_auth, "_client") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json = AsyncMock(return_value=response_data)
            mock_client.request = AsyncMock(return_value=mock_response)

            result = await client_no_auth.health_check()

            assert result == {"status": "ok"}

    @pytest.mark.asyncio
    async def test_get_current_user(self, client):
        """Test get_current_user method."""
        user_data = {
            "preferred_username": "testuser",
            "email": "test@example.com",
            "given_name": "Test",
            "family_name": "User",
            "roles": ["user"],
        }

        with patch.object(client, "_client") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json = AsyncMock(return_value=user_data)
            mock_client.request = AsyncMock(return_value=mock_response)

            result = await client.get_current_user()

            assert isinstance(result, UserInfo)
            assert result.preferred_username == "testuser"
            assert result.email == "test@example.com"
            assert result.roles == ["user"]

    @pytest.mark.asyncio
    async def test_upload_archive_string_path(self, client):
        """Test upload_archive with string file path."""
        file_path = "/path/to/test.zip"
        file_content = b"fake zip content"

        upload_data = {
            "message": "Upload successful",
            "original_filename": "test.zip",
            "uploaded_filename": "abc123.zip",
            "md5": "md5hash",
            "size": len(file_content),
        }

        with (
            patch("pathlib.Path.exists", return_value=True),
            patch("pathlib.Path.read_bytes", return_value=file_content),
            patch.object(client, "_client") as mock_client,
        ):
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json = AsyncMock(return_value=upload_data)
            mock_client.request = AsyncMock(return_value=mock_response)

            result = await client.upload_archive(file_path)

            assert isinstance(result, UploadResponse)
            assert result.original_filename == "test.zip"
            assert result.uploaded_filename == "abc123.zip"

    @pytest.mark.asyncio
    async def test_upload_archive_path_object(self, client):
        """Test upload_archive with Path object."""
        file_path = Path("/path/to/test.zip")
        file_content = b"fake zip content"

        upload_data = {
            "message": "Upload successful",
            "original_filename": "test.zip",
            "uploaded_filename": "abc123.zip",
            "md5": "md5hash",
            "size": len(file_content),
        }

        with (
            patch("pathlib.Path.exists", return_value=True),
            patch("pathlib.Path.read_bytes", return_value=file_content),
            patch.object(client, "_client") as mock_client,
        ):
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json = AsyncMock(return_value=upload_data)
            mock_client.request = AsyncMock(return_value=mock_response)

            result = await client.upload_archive(file_path)

            assert isinstance(result, UploadResponse)
            assert result.original_filename == "test.zip"

    @pytest.mark.asyncio
    async def test_upload_archive_file_not_found(self, client):
        """Test upload_archive with non-existent file."""
        file_path = "/path/to/nonexistent.zip"

        with patch("pathlib.Path.exists", return_value=False):
            with pytest.raises(ValidationError, match="File not found"):
                await client.upload_archive(file_path)

    @pytest.mark.asyncio
    async def test_upload_archive_invalid_extension(self, client):
        """Test upload_archive with invalid file extension."""
        file_path = "/path/to/test.txt"

        with (
            patch("pathlib.Path.exists", return_value=True),
            patch("pathlib.Path.read_bytes", return_value=b"fake content"),
        ):
            with pytest.raises(ValidationError, match="Only ZIP files are allowed"):
                await client.upload_archive(file_path)

    @pytest.mark.asyncio
    async def test_upload_archive_file_object(self, client):
        """Test upload_archive with file-like object."""
        file_content = b"fake zip content"

        upload_data = {
            "message": "Upload successful",
            "original_filename": "test.zip",
            "uploaded_filename": "abc123.zip",
            "md5": "md5hash",
            "size": len(file_content),
        }

        mock_file = AsyncMock()
        mock_file.read.return_value = file_content

        with patch.object(client, "_client") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json = AsyncMock(return_value=upload_data)
            mock_client.request = AsyncMock(return_value=mock_response)

            result = await client.upload_archive(mock_file, filename="test.zip")

            assert isinstance(result, UploadResponse)
            assert result.original_filename == "test.zip"

    @pytest.mark.asyncio
    async def test_upload_archive_file_object_no_filename(self, client):
        """Test upload_archive with file-like object but no filename."""
        mock_file = AsyncMock()

        with pytest.raises(ValidationError, match="filename is required"):
            await client.upload_archive(mock_file)

    @patch.dict("os.environ", {"MECAPY_API_URL": "https://api.mecapy.com"}, clear=True)
    @patch("mecapy.client.config")
    @patch("mecapy.client.MecapyAuth")
    def test_from_env_default_urls(self, mock_auth_class, mock_config):
        """Test from env with default URLs."""
        mock_config.api_url = "https://api.mecapy.com"
        mock_config.timeout = 30.0
        mock_auth = Mock()
        mock_auth_class.return_value = mock_auth

        client = MecaPyClient()

        assert client.api_url == "https://api.mecapy.com"
        assert client.auth == mock_auth

    @patch("mecapy.client.config")
    @patch("mecapy.client.MecapyAuth")
    def test_from_env_success(self, mock_auth_class, mock_config):
        """Test successful from env creation."""
        mock_config.api_url = "https://api.example.com"
        mock_config.timeout = 45.0
        mock_auth = Mock()
        mock_auth_class.return_value = mock_auth

        client = MecaPyClient()

        assert client.api_url == "https://api.example.com"
        assert client.auth == mock_auth
        assert client.timeout == 45.0

    @patch("mecapy.client.config")
    @patch("mecapy.client.MecapyAuth")
    def test_from_env_custom_urls(self, mock_auth_class, mock_config):
        """Test from env with custom URLs."""
        mock_config.api_url = "https://api.example.com"
        mock_config.timeout = 30.0
        mock_auth = Mock()
        mock_auth_class.return_value = mock_auth

        client = MecaPyClient()

        assert client.api_url == "https://api.example.com"
        assert client.auth == mock_auth  # Auth is always created now
        assert client.timeout == 30.0

    @pytest.mark.asyncio
    async def test_make_request_auth_token_exception(self, client):
        """Test request when getting auth token raises exception."""
        with patch.object(client.auth, "get_access_token", side_effect=Exception("Token error")):
            with pytest.raises(AuthenticationError, match="Failed to get access token: Token error"):
                await client._make_request("GET", "/test", authenticated=True)

    @pytest.mark.asyncio
    async def test_make_request_403_error(self, client):
        """Test request with 403 error."""
        with patch.object(client, "_client") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 403
            mock_client.request = AsyncMock(return_value=mock_response)

            with pytest.raises(AuthenticationError, match="Access forbidden"):
                await client._make_request("GET", "/test")

    @pytest.mark.asyncio
    async def test_make_request_4xx_error(self, client):
        """Test request with generic 4xx error."""
        with patch.object(client, "_client") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 400
            mock_response.text = "Bad Request"
            mock_client.request = AsyncMock(return_value=mock_response)

            with pytest.raises(ValidationError, match="Client error: Bad Request"):
                await client._make_request("GET", "/test")

    @pytest.mark.asyncio
    async def test_test_protected_route(self, client):
        """Test test_protected_route method."""
        mock_response_data = {
            "message": "Access granted",
            "user_info": {"preferred_username": "testuser", "email": "test@example.com", "roles": ["user"]},
            "endpoint": "/auth/protected",
        }

        with patch.object(client, "_make_request") as mock_request:
            mock_response = AsyncMock()
            mock_response.json = AsyncMock(return_value=mock_response_data)
            mock_request.return_value = mock_response

            result = await client.test_protected_route()

            mock_request.assert_called_once_with("GET", "/auth/protected")
            assert result.message == "Access granted"
            assert result.user_info.preferred_username == "testuser"
            assert result.endpoint == "/auth/protected"

    @pytest.mark.asyncio
    async def test_test_admin_route(self, client):
        """Test test_admin_route method."""
        mock_response_data = {"message": "Admin access granted", "admin_access": True, "endpoint": "/auth/admin"}

        with patch.object(client, "_make_request") as mock_request:
            mock_response = AsyncMock()
            mock_response.json = AsyncMock(return_value=mock_response_data)
            mock_request.return_value = mock_response

            result = await client.test_admin_route()

            mock_request.assert_called_once_with("GET", "/auth/admin")
            assert result.message == "Admin access granted"
            assert result.admin_access is True
            assert result.endpoint == "/auth/admin"

    def test_normalize_username_field_with_username(self):
        """Test _normalize_username_field with username field."""
        client = MecaPyClient.__new__(MecaPyClient)  # Skip __init__
        data = {"username": "testuser", "email": "test@example.com"}

        result = client._normalize_username_field(data)

        assert result["preferred_username"] == "testuser"
        assert result["username"] == "testuser"
        assert result["email"] == "test@example.com"

    def test_normalize_username_field_with_preferred_username(self):
        """Test _normalize_username_field with preferred_username already present."""
        client = MecaPyClient.__new__(MecaPyClient)  # Skip __init__
        data = {"preferred_username": "testuser", "username": "otheruser"}

        result = client._normalize_username_field(data)

        # Should not modify if preferred_username already exists
        assert result["preferred_username"] == "testuser"
        assert result["username"] == "otheruser"

    def test_normalize_username_field_non_dict(self):
        """Test _normalize_username_field with non-dict input."""
        client = MecaPyClient.__new__(MecaPyClient)  # Skip __init__
        data = "not a dict"

        result = client._normalize_username_field(data)

        assert result == "not a dict"

    def test_normalize_nested_user_info_with_username(self):
        """Test _normalize_nested_user_info with username in user_info."""
        client = MecaPyClient.__new__(MecaPyClient)  # Skip __init__
        data = {"message": "Hello", "user_info": {"username": "testuser", "email": "test@example.com"}}

        result = client._normalize_nested_user_info(data)

        assert result["user_info"]["preferred_username"] == "testuser"
        assert result["user_info"]["username"] == "testuser"
        assert result["message"] == "Hello"

    def test_normalize_nested_user_info_with_preferred_username(self):
        """Test _normalize_nested_user_info with preferred_username already present."""
        client = MecaPyClient.__new__(MecaPyClient)  # Skip __init__
        data = {"message": "Hello", "user_info": {"preferred_username": "testuser", "username": "otheruser"}}

        result = client._normalize_nested_user_info(data)

        # Should not modify if preferred_username already exists
        assert result["user_info"]["preferred_username"] == "testuser"
        assert result["user_info"]["username"] == "otheruser"

    def test_normalize_nested_user_info_no_user_info(self):
        """Test _normalize_nested_user_info without user_info field."""
        client = MecaPyClient.__new__(MecaPyClient)  # Skip __init__
        data = {"message": "Hello"}

        result = client._normalize_nested_user_info(data)

        assert result == {"message": "Hello"}

    def test_normalize_nested_user_info_non_dict(self):
        """Test _normalize_nested_user_info with non-dict input."""
        client = MecaPyClient.__new__(MecaPyClient)  # Skip __init__
        data = "not a dict"

        result = client._normalize_nested_user_info(data)

        assert result == "not a dict"

    @pytest.mark.asyncio
    async def test_json_with_awaitable_response(self):
        """Test _json method when response.json() returns an awaitable."""
        client = MecaPyClient.__new__(MecaPyClient)  # Skip __init__

        # Create a mock response where json() returns a coroutine
        mock_response = Mock()

        async def mock_json():
            return {"key": "value"}

        mock_response.json.return_value = mock_json()

        result = await client._json(mock_response)

        assert result == {"key": "value"}

    @pytest.mark.asyncio
    async def test_json_with_non_awaitable_response(self):
        """Test _json method when response.json() returns a regular value."""
        client = MecaPyClient.__new__(MecaPyClient)  # Skip __init__

        # Create a mock response where json() returns a regular dict
        mock_response = Mock()
        mock_response.json.return_value = {"key": "value"}

        result = await client._json(mock_response)

        assert result == {"key": "value"}
