# Claude AI Assistant Instructions - MecaPy Python SDK

## Repository Overview
Python client library for MecaPy API with:
- **Authentication**: Keycloak OAuth2/OIDC integration
- **Async Support**: Modern async/await patterns
- **Type Safety**: Full Pydantic models and type hints
- **Testing**: pytest with httpx mocking
- **Distribution**: PyPI package publication

## Critical Procedures

### 1. Dependency Management with UV
**⚠️ MANDATORY**: After ANY change to `pyproject.toml`, run:

```bash
uv lock
git add uv.lock
git commit -m "Update lockfile: [describe changes]"
```

**Never commit `pyproject.toml` changes without updating `uv.lock`**

### 2. PyPI Publication
- Automated via GitHub Actions on main branch pushes
- Uses `twine` for publication
- Requires PYPI_API_TOKEN secret in GitHub

### 3. Development Commands

#### Environment Setup
```bash
# Initialize development environment (installs uv, Python, creates venv)
task init

# Install dependencies only
task install
```

#### Testing
```bash
# Run unit tests with coverage
task test:unit

# Run interactive tests
task test:interactive

# Run all tests except production
task test:not_production
```

#### Code Quality
```bash
# Run all quality checks (lint + typecheck)
task check

# Format code and fix linting issues
task format
```

#### Version Management
```bash
# Show version information (git tag, installed package, last build)
task version

# Set a new version tag
task version:set VERSION=1.0.0

# Synchronize installed package with git tag version
task version:sync
```

#### Build and Publish
```bash
# Build package
task build

# Publish to TestPyPI
task publish:test

# Publish to PyPI
task publish:prod
```

## Key Configuration Files
- `pyproject.toml` - Dependencies, metadata, build config, and pytest configuration
- `taskfile.yml` - Development workflow automation with go-task
- `.python-version` - Python version specification for uv
- `sonar-project.properties` - SonarCloud settings (project: mecapy_python-sdk)
- `.github/workflows/ci.yml` - CI/CD and PyPI publication
- `dev/env.local` - Local development environment variables

## Testing Strategy
- Multi-version testing (Python 3.9-3.13)
- httpx mocking for API calls
- Authentication flow testing
- Type safety validation
- Coverage reporting to SonarCloud
- **Unit tests**: 100% code coverage with pytest markers
- **Warning filtering**: RuntimeWarnings from AsyncMock coroutines are filtered out in pyproject.toml
- **Configuration**: All pytest settings centralized in `pyproject.toml` (markers, filterwarnings, coverage)

## Common Issues
1. **Lockfile out of sync**: Run `uv lock` after dependency changes
2. **PyPI publication fails**: Check PYPI_API_TOKEN and version conflicts
3. **Multi-version CI**: Ensure compatibility across Python versions
4. **SonarCloud**: Badge tokens need to be updated in README

## Version Management
- Version defined in `mecapy/__version__.py`
- Automatically extracted by hatch for PyPI
- Follow semantic versioning (MAJOR.MINOR.PATCH)
- Update version before major releases