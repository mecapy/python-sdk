# MecaPy SDK

[![CI](https://github.com/mecapy/python-sdk/workflows/CI/badge.svg)](https://github.com/mecapy/python-sdk/actions/workflows/ci.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=mecapy_python-sdk&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=mecapy_python-sdk)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=mecapy_python-sdk&metric=coverage)](https://sonarcloud.io/summary/new_code?id=mecapy_python-sdk)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=mecapy_python-sdk&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=mecapy_python-sdk)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=mecapy_python-sdk&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=mecapy_python-sdk)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PyPI Version](https://img.shields.io/pypi/v/mecapy-sdk)](https://pypi.org/project/mecapy-sdk/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/mecapy-sdk)](https://pypi.org/project/mecapy-sdk/)

Python SDK for MecaPy API - A clean, simple, and robust client library.

## Features

- 🔐 **Keycloak Authentication** - Full support for OAuth2/OIDC with automatic token refresh
- 🚀 **Async/Await Support** - Modern Python async programming
- 📝 **Type Hints** - Full type safety with Pydantic models
- 🛡️ **Error Handling** - Comprehensive exception handling
- 🧪 **Well Tested** - Extensive test coverage
- 📚 **Environment Variables** - Easy configuration management

## Installation

```bash
pip install mecapy-sdk
```

## Quick Start

### Basic Usage

```python
import asyncio
from mecapy import MecaPyClient

async def main():
    # Simple usage with default production URLs
    # Only credentials are needed for authentication
    async with MecaPyClient.from_env() as client:
        # Get current user info
        user = await client.get_current_user()
        print(f"Hello, {user.preferred_username}!")

        # Upload a file
        upload_result = await client.upload_archive("my-archive.zip")
        print(f"Uploaded: {upload_result.uploaded_filename}")

asyncio.run(main())
```

### Using Environment Variables

```python
import asyncio
from mecapy import MecaPyClient

# Set environment variables (only credentials required):
# MECAPY_USERNAME=your-username
# MECAPY_PASSWORD=your-password
#
# Optional overrides for on-premise:
# MECAPY_API_URL=https://your-api.company.com
# MECAPY_KEYCLOAK_URL=https://your-auth.company.com

async def main():
    # Create client - uses production URLs by default
    async with MecaPyClient.from_env() as client:
        # Check API health
        health = await client.health_check()
        print(f"API Status: {health['status']}")

        # Get API info
        info = await client.get_root()
        print(f"API Version: {info.version}")

asyncio.run(main())
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MECAPY_API_URL` | MecaPy API base URL | `https://api.mecapy.com` |
| `MECAPY_KEYCLOAK_URL` | Keycloak server URL | `https://auth.mecapy.com` |
| `MECAPY_REALM` | Keycloak realm | `mecapy` |
| `MECAPY_CLIENT_ID` | Keycloak client ID | `mecapy-api-public` |
| `MECAPY_USERNAME` | Username for auth | Required for authentication |
| `MECAPY_PASSWORD` | Password for auth | Required for authentication |
| `MECAPY_TIMEOUT` | Request timeout (seconds) | `30.0` |

**🎯 For most users**: Only set `MECAPY_USERNAME` and `MECAPY_PASSWORD`. The SDK uses MecaPy production URLs by default.

**🏢 For on-premise installations**: Override `MECAPY_API_URL` and `MECAPY_KEYCLOAK_URL` as needed.

### .env File Support

**Minimal .env file (production):**
```bash
MECAPY_USERNAME=your-username
MECAPY_PASSWORD=your-password
```

**Complete .env file (on-premise):**
```bash
MECAPY_API_URL=https://your-api.company.com
MECAPY_KEYCLOAK_URL=https://your-auth.company.com
MECAPY_REALM=mecapy
MECAPY_CLIENT_ID=mecapy-api-public
MECAPY_USERNAME=your-username
MECAPY_PASSWORD=your-password
```

Then load it:

```python
import asyncio
from dotenv import load_dotenv
from mecapy import MecaPyClient

load_dotenv()

async def main():
    async with MecaPyClient.from_env() as client:
        user = await client.get_current_user()
        print(f"Authenticated as: {user.preferred_username}")

asyncio.run(main())
```

## API Reference

### MecaPyClient

#### Methods

##### Authentication Endpoints

- `get_current_user() -> UserInfo` - Get current user information
- `test_protected_route() -> ProtectedResponse` - Test protected endpoint access
- `test_admin_route() -> AdminResponse` - Test admin endpoint access (requires admin role)

##### File Upload Endpoints

- `upload_archive(file, filename=None) -> UploadResponse` - Upload ZIP archive

##### Utility Endpoints

- `get_root() -> APIResponse` - Get API information
- `health_check() -> Dict[str, str]` - Check API health

### MecapyAuth

#### Methods

- `set_credentials(username, password)` - Set authentication credentials
- `get_access_token() -> str` - Get valid access token (with auto-refresh)
- `logout()` - Clear stored tokens

#### Class Methods

- `from_env() -> MecapyAuth` - Create instance from environment variables

## Error Handling

The SDK provides specific exception types for different error scenarios:

```python
from mecapy import MecaPyClient
from mecapy.exceptions import (
    AuthenticationError,
    ValidationError,
    NotFoundError,
    ServerError,
    NetworkError
)

async def handle_errors():
    async with MecaPyClient.from_env() as client:
        try:
            user = await client.get_current_user()
        except AuthenticationError:
            print("Authentication failed - check credentials")
        except ValidationError as e:
            print(f"Validation failed: {e.message}")
        except NotFoundError:
            print("Resource not found")
        except ServerError as e:
            print(f"Server error: {e.status_code}")
        except NetworkError:
            print("Network connection failed")
```

## Data Models

All API responses are validated using Pydantic models:

### UserInfo

```python
class UserInfo(BaseModel):
    preferred_username: str
    email: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    roles: List[str] = []
```

### UploadResponse

```python
class UploadResponse(BaseModel):
    message: str
    original_filename: str
    uploaded_filename: str
    md5: str
    size: int
```

## Examples

### File Upload

```python
import asyncio
from pathlib import Path
from mecapy import MecaPyClient

async def upload_file():
    async with MecaPyClient.from_env() as client:
        # Upload from file path
        result = await client.upload_archive("data.zip")
        print(f"File uploaded: {result.uploaded_filename}")

        # Upload from Path object
        file_path = Path("archive.zip")
        result = await client.upload_archive(file_path)
        print(f"MD5: {result.md5}")

        # Upload from file-like object
        with open("data.zip", "rb") as f:
            result = await client.upload_archive(f, filename="data.zip")
            print(f"Size: {result.size} bytes")

asyncio.run(upload_file())
```

### User Management

```python
import asyncio
from mecapy import MecaPyClient

async def user_info():
    async with MecaPyClient.from_env() as client:
        # Get current user
        user = await client.get_current_user()
        print(f"Username: {user.preferred_username}")
        print(f"Email: {user.email}")
        print(f"Roles: {', '.join(user.roles)}")

        # Test role-based access
        try:
            admin_response = await client.test_admin_route()
            print("Admin access granted!")
        except AuthenticationError:
            print("Admin access denied")

asyncio.run(user_info())
```

### Custom Authentication

```python
import asyncio
from mecapy import MecaPyClient
from mecapy.auth import MecapyAuth


async def custom_auth():
    # Create auth with custom settings
    auth = MecapyAuth(
        keycloak_url="https://custom-auth.example.com",
        realm="custom-realm",
        client_id="custom-client"
    )

    # Set credentials dynamically
    auth.set_credentials("user@example.com", "secure-password")

    async with MecaPyClient("https://api.example.com", auth=auth) as client:
        user = await client.get_current_user()
        print(f"Authenticated: {user.preferred_username}")


asyncio.run(custom_auth())
```

## Development

### Setup

```bash
git clone https://github.com/mecapy/python-sdk.git
cd python-sdk
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=mecapy

# Run specific test types
pytest -m unit
pytest -m integration
```

### Code Quality

```bash
# Format code
ruff format

# Lint code
ruff check

# Type checking
mypy mecapy
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Support

- 📖 [Documentation](https://mecapy.github.io/python-sdk)
- 🐛 [Issue Tracker](https://github.com/mecapy/python-sdk/issues)
- 💬 [Discussions](https://github.com/mecapy/python-sdk/discussions)

---

Made with ❤️ by the MecaPy team
