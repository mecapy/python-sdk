"""Tests for MecaPy client."""

import pytest
from unittest.mock import AsyncMock, patch, mock_open
from pathlib import Path
import httpx

from mecapy_sdk import MecaPyClient
from mecapy_sdk.models import UserInfo, UploadResponse, APIResponse
from mecapy_sdk.exceptions import AuthenticationError, ValidationError, NotFoundError, ServerError, NetworkError


@pytest.mark.unit
class TestMecaPyClient:
    """Test MecaPyClient class."""
    
    def test_init(self, mock_auth):
        """Test client initialization."""
        client = MecaPyClient(
            api_url="https://api.example.com/",
            auth=mock_auth,
            timeout=15.0
        )
        
        assert client.api_url == "https://api.example.com"
        assert client.auth == mock_auth
        assert client.timeout == 15.0
    
    @pytest.mark.asyncio
    async def test_context_manager(self, mock_auth):
        """Test client as async context manager."""
        async with MecaPyClient("https://api.example.com", auth=mock_auth) as client:
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
            mock_response = AsyncMock()
            mock_response.status_code = 422
            mock_response.json.return_value = {"detail": "Validation failed"}
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
        response_data = {
            "message": "Welcome to API",
            "status": "running",
            "version": "1.0.0"
        }
        
        with patch.object(client_no_auth, "_client") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = response_data
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
            mock_response.json.return_value = response_data
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
            "roles": ["user"]
        }
        
        with patch.object(client, "_client") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = user_data
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
            "size": len(file_content)
        }
        
        with patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_bytes", return_value=file_content), \
             patch.object(client, "_client") as mock_client:
            
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = upload_data
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
            "size": len(file_content)
        }
        
        with patch.object(file_path, "exists", return_value=True), \
             patch.object(file_path, "read_bytes", return_value=file_content), \
             patch.object(client, "_client") as mock_client:
            
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = upload_data
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
        
        with patch("pathlib.Path.exists", return_value=True):
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
            "size": len(file_content)
        }
        
        mock_file = AsyncMock()
        mock_file.read.return_value = file_content
        
        with patch.object(client, "_client") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = upload_data
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
    
    def test_from_env_default_urls(self):
        """Test from_env with default URLs."""
        with patch.dict("os.environ", {}, clear=True), \
             patch("mecapy_sdk.client.KeycloakAuth.from_env") as mock_auth_from_env:
            
            mock_auth = AsyncMock()
            mock_auth_from_env.return_value = mock_auth
            
            client = MecaPyClient.from_env()
            
            assert client.api_url == "https://api.mecapy.com"
            assert client.auth == mock_auth
    
    def test_from_env_success(self):
        """Test successful from_env creation."""
        env_vars = {
            "MECAPY_API_URL": "https://api.example.com",
            "MECAPY_KEYCLOAK_URL": "https://auth.example.com",
            "MECAPY_TIMEOUT": "45.0"
        }
        
        with patch.dict("os.environ", env_vars), \
             patch("mecapy_sdk.client.KeycloakAuth.from_env") as mock_auth_from_env:
            
            mock_auth = AsyncMock()
            mock_auth_from_env.return_value = mock_auth
            
            client = MecaPyClient.from_env()
            
            assert client.api_url == "https://api.example.com"
            assert client.auth == mock_auth
            assert client.timeout == 45.0
    
    def test_from_env_custom_urls(self):
        """Test from_env with custom URLs."""
        env_vars = {
            "MECAPY_API_URL": "https://api.example.com",
            "MECAPY_KEYCLOAK_URL": "https://auth.example.com"
        }
        
        with patch.dict("os.environ", env_vars), \
             patch("mecapy_sdk.client.KeycloakAuth.from_env") as mock_auth_from_env:
            
            mock_auth = AsyncMock()
            mock_auth_from_env.return_value = mock_auth
            
            client = MecaPyClient.from_env()
            
            assert client.api_url == "https://api.example.com"
            assert client.auth == mock_auth
            assert client.timeout == 30.0
            
            # Verify that KeycloakAuth.from_env was called (it will use the custom URL)
            mock_auth_from_env.assert_called_once()