"""Exception classes for MecaPy SDK."""

from typing import Any


class MecaPyError(Exception):
    """Base exception for all MecaPy SDK errors."""

    def __init__(self, message: str, status_code: int | None = None, response_data: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.response_data = response_data or {}


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


# -----------------------------------------------------------------------------
# Authentication Based Error:
# -----------------------------------------------------------------------------
class AuthenticationError(MecaPyError):
    """Base exception for authentication errors."""


class NoFreePortError(AuthenticationError):
    """Raised when no free port is found in the provided list."""

    def __init__(self, ports: tuple[int, ...]) -> None:
        super().__init__(f"No free port found among {ports}")


class NoAuthCodeError(AuthenticationError):
    """Raised when no authorization code is received from OAuth provider."""

    def __init__(self) -> None:
        super().__init__("No authorization code received from OAuth provider")


class NoAccessTokenError(AuthenticationError):
    """Raised when no access token is found in token response."""

    def __init__(self, message: str = "No access token found in token response") -> None:
        super().__init__(message)
