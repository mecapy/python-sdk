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
- Version managed via `mecapy_sdk/__version__.py`

### 3. Development Commands
```bash
# Install dependencies
uv sync --extra dev

# Run tests with coverage
uv run pytest --cov=mecapy_sdk --cov-report=xml --cov-report=html

# Lint (currently disabled in CI)
uv run ruff check .
uv run ruff format .

# Type check (currently disabled in CI)
uv run mypy mecapy_sdk

# Build package
uv build

```

## Key Configuration Files
- `pyproject.toml` - Dependencies, metadata, and build config
- `sonar-project.properties` - SonarCloud settings (project: mecapy_python-sdk)
- `mecapy_sdk/__version__.py` - Single source of truth for version
- `.github/workflows/ci.yml` - CI/CD and PyPI publication

## Testing Strategy
- Multi-version testing (Python 3.9-3.13)
- httpx mocking for API calls
- Authentication flow testing
- Type safety validation
- Coverage reporting to SonarCloud

## Common Issues
1. **Lockfile out of sync**: Run `uv lock` after dependency changes
2. **PyPI publication fails**: Check PYPI_API_TOKEN and version conflicts
3. **Multi-version CI**: Ensure compatibility across Python versions
4. **SonarCloud**: Badge tokens need to be updated in README

## Version Management
- Version defined in `mecapy_sdk/__version__.py`
- Automatically extracted by hatch for PyPI
- Follow semantic versioning (MAJOR.MINOR.PATCH)
- Update version before major releases