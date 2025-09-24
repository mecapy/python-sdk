"""Data models for MecaPy SDK."""

from pydantic import BaseModel, Field


class UserInfo(BaseModel):
    """User information model."""

    preferred_username: str = Field(..., description="User's preferred username")
    email: str | None = Field(None, description="User's email address")
    given_name: str | None = Field(None, description="User's first name")
    family_name: str | None = Field(None, description="User's last name")
    roles: list[str] = Field(default_factory=list, description="User's roles")


class UploadResponse(BaseModel):
    """Response model for file upload."""

    message: str = Field(..., description="Success message")
    original_filename: str = Field(..., description="Original filename")
    uploaded_filename: str = Field(..., description="Generated filename on server")
    md5: str = Field(..., description="MD5 hash of the file")
    size: int = Field(..., description="File size in bytes")


class APIResponse(BaseModel):
    """Generic API response model."""

    message: str = Field(..., description="Response message")
    status: str = Field(..., description="Response status")
    version: str | None = Field(None, description="API version")


class ProtectedResponse(BaseModel):
    """Response model for protected endpoints."""

    message: str = Field(..., description="Response message")
    user_info: UserInfo = Field(..., description="User information")
    endpoint: str = Field(..., description="Endpoint identifier")


class AdminResponse(BaseModel):
    """Response model for admin endpoints."""

    message: str = Field(..., description="Response message")
    admin_access: bool = Field(..., description="Admin access confirmation")
    endpoint: str = Field(..., description="Endpoint identifier")
