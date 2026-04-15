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
- 🗂️ **JSON Test Runner** - Generic JSON-driven test runner for MecaPy packages (`mecapy.testing`)

## Installation

```bash
pip install mecapy-sdk
```

## Quick Start

### Basic Usage

```python
from mecapy import MecaPyClient

# Simple usage with default authentication (auto-detection)
client = MecaPyClient()

# Get current user info
user = client.get_current_user()
print(f"Hello, {user.preferred_username}!")

# Upload a file
upload_result = client.upload_archive("my-archive.zip")
print(f"Uploaded: {upload_result.uploaded_filename}")
```

### Token Authentication (Recommended for CI/CD)

```python
from mecapy import MecaPyClient, Auth

# Using service account token
auth = Auth.Token("your-long-lived-service-account-token")
client = MecaPyClient(auth=auth)

# Get current user info
user = client.get_current_user()
print(f"Authenticated as: {user.preferred_username}")
```

### Environment Variables

```python
from mecapy import MecaPyClient

# Set environment variables:
# MECAPY_TOKEN=your-service-account-token  # For token auth
#
# OR for OAuth2:
# MECAPY_USERNAME=your-username
# MECAPY_PASSWORD=your-password
#
# Optional overrides for on-premise:
# MECAPY_API_URL=https://your-api.company.com
# MECAPY_KEYCLOAK_URL=https://your-auth.company.com

# Create client - uses auto-detection
client = MecaPyClient()

# Check API health
health = client.health_check()
print(f"API Status: {health['status']}")

# Get API info
info = client.get_root()
print(f"API Version: {info.version}")
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MECAPY_API_URL` | MecaPy API base URL | `https://api.mecapy.com` |
| `MECAPY_TOKEN` | Service account token | None (triggers auto-detection) |
| `MECAPY_KEYCLOAK_URL` | Keycloak server URL | `https://auth.mecapy.com` |
| `MECAPY_REALM` | Keycloak realm | `mecapy` |
| `MECAPY_CLIENT_ID` | Keycloak client ID | `mecapy-api-public` |
| `MECAPY_USERNAME` | Username for OAuth2 | None |
| `MECAPY_PASSWORD` | Password for OAuth2 | None |
| `MECAPY_TIMEOUT` | Request timeout (seconds) | `30.0` |

**🎯 For most users**: Set `MECAPY_TOKEN` with your service account token for the simplest experience.

**🔄 For interactive use**: Set `MECAPY_USERNAME` and `MECAPY_PASSWORD` for OAuth2 browser-based login.

**🏢 For on-premise installations**: Override `MECAPY_API_URL` and `MECAPY_KEYCLOAK_URL` as needed.

### .env File Support

**Minimal .env file (token auth):**
```bash
MECAPY_TOKEN=your-service-account-token
```

**OAuth2 .env file:**
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
MECAPY_TOKEN=your-service-account-token
```

Then load it:

```python
from dotenv import load_dotenv
from mecapy import MecaPyClient

load_dotenv()

client = MecaPyClient()
user = client.get_current_user()
print(f"Authenticated as: {user.preferred_username}")
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

### Authentication Classes

#### Auth (Namespace)

- `Auth.Token(token: str)` - Create token-based authentication
- `Auth.ServiceAccount(client_id, client_secret)` - Create service account authentication
- `Auth.OAuth2()` - Create interactive OAuth2 authentication
- `Auth.Default()` - Create auto-detection authentication

#### MecaPyClient Class Methods

- `MecaPyClient.from_env()` - Create client with auto-detection
- `MecaPyClient.from_token(token)` - Create client with token authentication

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

client = MecaPyClient()

try:
    user = client.get_current_user()
    print(f"Hello, {user.preferred_username}!")
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
from pathlib import Path
from mecapy import MecaPyClient, Auth

# Using token authentication
auth = Auth.Token("your-service-account-token")
with MecaPyClient(auth=auth) as client:
    # Upload from file path
    result = client.upload_archive("data.zip")
    print(f"File uploaded: {result.uploaded_filename}")

    # Upload from Path object
    file_path = Path("archive.zip")
    result = client.upload_archive(file_path)
    print(f"MD5: {result.md5}")

    # Upload from file-like object
    with open("data.zip", "rb") as f:
        result = client.upload_archive(f, filename="data.zip")
        print(f"Size: {result.size} bytes")
```

### User Management

```python
from mecapy import MecaPyClient, Auth
from mecapy.exceptions import AuthenticationError

# Using auto-detection (will try MECAPY_TOKEN, then OAuth2)
client = MecaPyClient()

# Get current user
user = client.get_current_user()
print(f"Username: {user.preferred_username}")
print(f"Email: {user.email}")
print(f"Roles: {', '.join(user.roles)}")

# Test role-based access
try:
    admin_response = client.test_admin_route()
    print("Admin access granted!")
except AuthenticationError:
    print("Admin access denied")
```

### Advanced Authentication Examples

```python
from mecapy import MecaPyClient, Auth

# 1. Token authentication (simplest for CI/CD)
auth = Auth.Token("your-service-account-token")
client = MecaPyClient(auth=auth)

# 2. Service account with client credentials (automatic token refresh)
auth = Auth.ServiceAccount(
    client_id="mecapy-sdk-service",
    client_secret="your-client-secret"
)
client = MecaPyClient(auth=auth)

# 3. Interactive OAuth2 (browser-based login)
auth = Auth.OAuth2()
client = MecaPyClient(auth=auth)  # Will open browser for login

# 4. Custom Keycloak configuration
auth = Auth.ServiceAccount(
    client_id="custom-client",
    client_secret="custom-secret",
    keycloak_url="https://custom-auth.example.com",
    realm="custom-realm"
)
client = MecaPyClient("https://api.example.com", auth=auth)

user = client.get_current_user()
print(f"Authenticated: {user.preferred_username}")
```

## JSON Test Runner (`mecapy.testing`)

Le SDK inclut un test runner générique JSON-driven permettant aux experts métier d'écrire des cas de test sans code Python.

### Principe

Les cas de test sont définis dans des fichiers `test_*.json`. Le runner charge ces fichiers, appelle dynamiquement les fonctions Python référencées et compare les résultats aux valeurs attendues.

```json
{
  "handler": "handler:ma_fonction",
  "description": "Tests de ma fonction de calcul",
  "test_cases": [
    {
      "name": "cas_nominal",
      "description": "Cas nominal avec valeurs standard",
      "request": {
        "param1": { "a": 10, "b": 1.5 },
        "param2": { "x": 100 }
      },
      "expected": {
        "resultat": 42.0,
        "valide": true
      },
      "tolerance": { "numeric": 0.1 }
    }
  ]
}
```

### Utilisation en ligne de commande

```bash
# Lancer les tests du répertoire tests/
mecapy-test tests/

# Avec un répertoire de module à ajouter au sys.path (sinon déduit automatiquement)
mecapy-test tests/ --sys-path /path/to/my/handler
```

### Utilisation programmatique

```python
from pathlib import Path
from mecapy.testing import TestRunner

runner = TestRunner(Path("tests"))
runner.run_all_tests()  # Quitte avec code 0 (succès) ou 1 (échec)
```

### Fonctionnalités

- **Import dynamique** : le module Python est importé à la volée depuis la clé `handler` du JSON (`"module:fonction"`)
- **Comparaison partielle** : seules les clés présentes dans `expected` sont vérifiées
- **Tolérance configurable** : chaque cas de test définit sa propre tolérance numérique
- **CI/CD-ready** : code de sortie `0` (succès) ou `1` (échec)
- **Affichage coloré** : résumé avec statistiques et détail des échecs

### Format du handler

| Format | Exemple | Description |
|--------|---------|-------------|
| `module:fonction` | `handler:calculer` | Fonction au niveau module |
| `module.Classe:methode` | `handler.Calc:run` | Méthode de classe |

## Development

### Setup

```bash
git clone https://github.com/mecapy/python-sdk.git
cd python-sdk

# Initialize development environment
task init

# Or manually with uv
uv sync --group dev
```

### Running Tests

```bash
# Run unit tests
task test:unit

# Run all tests
task test

# Run interactive tests
task test:interactive
```

### Code Quality

```bash
# Format code and fix linting
task format

# Run all quality checks (ruff + mypy)
task check

# Build package
task build
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
