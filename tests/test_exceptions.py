"""Tests for exception classes."""

import pytest

from mecapy.exceptions import (
    AuthenticationError,
    MecaPyError,
    NetworkError,
    NoAccessTokenError,
    NoAuthCodeError,
    NoFreePortError,
    NotFoundError,
    ServerError,
    ValidationError,
)


@pytest.mark.unit
class TestExceptions:
    """Test exception classes."""

    def test_mecapy_error_base(self):
        """Test base MecaPyError exception."""
        error = MecaPyError("Base error")
        assert str(error) == "Base error"

    def test_authentication_error(self):
        """Test AuthenticationError exception."""
        error = AuthenticationError("Auth failed")
        assert str(error) == "Auth failed"
        assert isinstance(error, MecaPyError)

    def test_validation_error_with_details(self):
        """Test ValidationError with status code and details."""
        error = ValidationError("Validation failed", 422, {"field": "error"})
        assert str(error) == "Validation failed"
        assert error.status_code == 422

    def test_validation_error_simple(self):
        """Test ValidationError with just message."""
        error = ValidationError("Simple validation error")
        assert str(error) == "Simple validation error"

    def test_server_error(self):
        """Test ServerError exception."""
        error = ServerError("Server error", 500)
        assert str(error) == "Server error"
        assert error.status_code == 500
        assert isinstance(error, MecaPyError)

    def test_not_found_error(self):
        """Test NotFoundError exception."""
        error = NotFoundError("Resource not found")
        assert str(error) == "Resource not found"
        assert isinstance(error, MecaPyError)

    def test_network_error(self):
        """Test NetworkError exception."""
        error = NetworkError("Network failed")
        assert str(error) == "Network failed"
        assert isinstance(error, MecaPyError)

    def test_no_free_port_error(self):
        """Test NoFreePortError exception."""
        ports = (8085, 8086, 8087)
        error = NoFreePortError(ports)
        assert "No free port found" in str(error)
        assert str(ports) in str(error)
        assert isinstance(error, AuthenticationError)

    def test_no_auth_code_error(self):
        """Test NoAuthCodeError exception."""
        error = NoAuthCodeError()
        assert "No authorization code received" in str(error)
        assert isinstance(error, AuthenticationError)

    def test_no_access_token_error_default(self):
        """Test NoAccessTokenError with default message."""
        error = NoAccessTokenError()
        assert "No access token found" in str(error)
        assert isinstance(error, AuthenticationError)

    def test_no_access_token_error_custom(self):
        """Test NoAccessTokenError with custom message."""
        error = NoAccessTokenError("Custom token error")
        assert str(error) == "Custom token error"
        assert isinstance(error, AuthenticationError)
