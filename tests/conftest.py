"""Pytest configuration and fixtures."""

from unittest.mock import Mock

import pytest

from mecapy import MecaPyClient
from mecapy.auth import AuthBase


@pytest.fixture
def mock_auth():
    """Mock AuthBase instance."""
    auth = Mock(spec=AuthBase)
    auth.get_access_token.return_value = "mock_token"
    auth.__call__ = Mock(side_effect=lambda req: setattr(req.headers, "Authorization", "Bearer mock_token") or req)
    return auth


@pytest.fixture
def client():
    """MecaPyClient instance with mock auth."""
    mock_auth = Mock(spec=AuthBase)
    mock_auth.get_access_token.return_value = "mock_token"
    mock_auth.__call__ = Mock(side_effect=lambda req: setattr(req.headers, "Authorization", "Bearer mock_token") or req)

    client = MecaPyClient(api_url="https://api.example.com", auth=mock_auth, timeout=10.0)
    return client


@pytest.fixture
def client_no_auth():
    """MecaPyClient instance without auth for public endpoints."""
    client = MecaPyClient(api_url="https://api.example.com", timeout=10.0)
    client.auth = None  # Set to None for public endpoints
    return client
