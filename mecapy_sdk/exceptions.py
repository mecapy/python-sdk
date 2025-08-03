"""Exception classes for MecaPy SDK."""

from typing import Dict, Any, Optional


class MecaPyError(Exception):
    """Base exception for all MecaPy SDK errors."""
    
    def __init__(self, message: str, status_code: Optional[int] = None, response_data: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.response_data = response_data or {}


class AuthenticationError(MecaPyError):
    """Raised when authentication fails."""
    pass


class ValidationError(MecaPyError):
    """Raised when request validation fails."""
    pass


class NotFoundError(MecaPyError):
    """Raised when a resource is not found."""
    pass


class ServerError(MecaPyError):
    """Raised when the server returns a 5xx error."""
    pass


class NetworkError(MecaPyError):
    """Raised when a network error occurs."""
    pass