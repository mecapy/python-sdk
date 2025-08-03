"""Pytest configuration and fixtures."""

import pytest
from unittest.mock import AsyncMock
from mecapy_sdk import MecaPyClient
from mecapy_sdk.auth import KeycloakAuth


@pytest.fixture
def mock_auth():
    """Mock KeycloakAuth instance."""
    auth = AsyncMock(spec=KeycloakAuth)
    auth.get_access_token.return_value = "mock_token"
    return auth


@pytest.fixture
def client(mock_auth):
    """MecaPyClient instance with mock auth."""
    return MecaPyClient(
        api_url="https://api.example.com",
        auth=mock_auth,
        timeout=10.0
    )


@pytest.fixture
def client_no_auth():
    """MecaPyClient instance without auth."""
    return MecaPyClient(
        api_url="https://api.example.com",
        auth=None,
        timeout=10.0
    )