"""Tests for configuration module."""

import pytest

from mecapy.config import AuthConfig, Config, config


@pytest.mark.unit
class TestAuthConfig:
    """Test AuthConfig class."""

    def test_get_oidc_discovery_url_with_trailing_slash(self):
        """Test get_oidc_discovery_url with trailing slash in issuer."""
        auth_config = AuthConfig(
            issuer="https://auth.example.com/realms/test/",
            client_id="test-client",
            realm="test"
        )

        result = auth_config.get_oidc_discovery_url()

        assert result == "https://auth.example.com/realms/test/.well-known/openid-configuration"

    def test_get_oidc_discovery_url_without_trailing_slash(self):
        """Test get_oidc_discovery_url without trailing slash in issuer."""
        auth_config = AuthConfig(
            issuer="https://auth.example.com/realms/test",
            client_id="test-client",
            realm="test"
        )

        result = auth_config.get_oidc_discovery_url()

        assert result == "https://auth.example.com/realms/test/.well-known/openid-configuration"


@pytest.mark.unit
class TestConfig:
    """Test Config class."""

    def test_config_instance_exists(self):
        """Test that global config instance exists."""
        assert config is not None
        assert isinstance(config, Config)
        assert hasattr(config, 'auth')
        assert hasattr(config, 'api_url')
        assert hasattr(config, 'timeout')