"""MecaPy SDK - Python client for MecaPy API."""

from .__version__ import __version__
from .client import MecaPyClient
from .exceptions import MecaPyError, AuthenticationError, ValidationError, NotFoundError

__all__ = [
    "__version__",
    "MecaPyClient",
    "MecaPyError",
    "AuthenticationError", 
    "ValidationError",
    "NotFoundError",
]