"""Pytest configuration and fixtures."""

from unittest.mock import AsyncMock

import pytest

from mecapy import MecaPyClient
from mecapy.auth import MecapyAuth


@pytest.fixture
def mock_auth():
    """Mock MecapyAuth instance."""
    auth = AsyncMock(spec=MecapyAuth)
    auth.get_token.return_value = {"access_token": "mock_token"}
    auth.get_session.return_value = AsyncMock()
    return auth


@pytest.fixture
def client(mock_auth):
    """MecaPyClient instance with mock auth."""
    return MecaPyClient(api_url="https://api.example.com", auth=mock_auth, timeout=10.0)


@pytest.fixture
def client_no_auth():
    """MecaPyClient instance without auth."""
    return MecaPyClient(api_url="https://api.example.com", auth=None, timeout=10.0)
