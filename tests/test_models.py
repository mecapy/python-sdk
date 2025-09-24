"""Tests for data models."""

import pytest
from pydantic import ValidationError as PydanticValidationError

from mecapy.models import AdminResponse, APIResponse, ProtectedResponse, UploadResponse, UserInfo


@pytest.mark.unit
class TestModels:
    """Test data models."""

    def test_user_info_minimal(self):
        """Test UserInfo with minimal data."""
        data = {"preferred_username": "testuser"}
        user = UserInfo(**data)

        assert user.preferred_username == "testuser"
        assert user.email is None
        assert user.given_name is None
        assert user.family_name is None
        assert user.roles == []

    def test_user_info_complete(self):
        """Test UserInfo with complete data."""
        data = {
            "preferred_username": "testuser",
            "email": "test@example.com",
            "given_name": "Test",
            "family_name": "User",
            "roles": ["user", "admin"],
        }
        user = UserInfo(**data)

        assert user.preferred_username == "testuser"
        assert user.email == "test@example.com"
        assert user.given_name == "Test"
        assert user.family_name == "User"
        assert user.roles == ["user", "admin"]

    def test_user_info_missing_username(self):
        """Test UserInfo validation with missing username."""
        data = {"email": "test@example.com"}

        with pytest.raises(PydanticValidationError):
            UserInfo(**data)

    def test_upload_response(self):
        """Test UploadResponse model."""
        data = {
            "message": "Upload successful",
            "original_filename": "test.zip",
            "uploaded_filename": "abc123.zip",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "size": 1024,
        }
        response = UploadResponse(**data)

        assert response.message == "Upload successful"
        assert response.original_filename == "test.zip"
        assert response.uploaded_filename == "abc123.zip"
        assert response.md5 == "d41d8cd98f00b204e9800998ecf8427e"
        assert response.size == 1024

    def test_upload_response_missing_fields(self):
        """Test UploadResponse validation with missing fields."""
        data = {"message": "Upload successful"}

        with pytest.raises(PydanticValidationError):
            UploadResponse(**data)

    def test_api_response(self):
        """Test APIResponse model."""
        data = {"message": "Welcome to API", "status": "running", "version": "1.0.0"}
        response = APIResponse(**data)

        assert response.message == "Welcome to API"
        assert response.status == "running"
        assert response.version == "1.0.0"

    def test_api_response_no_version(self):
        """Test APIResponse without version."""
        data = {"message": "Welcome to API", "status": "running"}
        response = APIResponse(**data)

        assert response.message == "Welcome to API"
        assert response.status == "running"
        assert response.version is None

    def test_protected_response(self):
        """Test ProtectedResponse model."""
        data = {
            "message": "Hello, testuser!",
            "user_info": {"preferred_username": "testuser", "email": "test@example.com", "roles": ["user"]},
            "endpoint": "protected",
        }
        response = ProtectedResponse(**data)

        assert response.message == "Hello, testuser!"
        assert isinstance(response.user_info, UserInfo)
        assert response.user_info.preferred_username == "testuser"
        assert response.endpoint == "protected"

    def test_admin_response(self):
        """Test AdminResponse model."""
        data = {"message": "Hello Admin!", "admin_access": True, "endpoint": "admin_only"}
        response = AdminResponse(**data)

        assert response.message == "Hello Admin!"
        assert response.admin_access is True
        assert response.endpoint == "admin_only"
