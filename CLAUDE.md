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
# Run all quality checks (lint + typecheck with mypy and ty)
task check

# Format code and fix linting issues
task format

# Run type checking with both mypy and ty
task typecheck

# Run type checking with mypy only
task typecheck:mypy

# Run type checking with ty only (fast, experimental)
task typecheck:ty
```

#### Version Management
```bash
# Show version information (git tag, installed package, last build)
task version

# Set version tag + update dev environment + build package (all-in-one)
task version:set VERSION=1.0.0

# Force complete version reset (manual cleanup)
task version:reset
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
- **Dynamic versioning** via `uv-dynamic-versioning` from Git tags
- **Semantic versioning** (MAJOR.MINOR.PATCH) with git tags
- **Development versions** automatically generated between tags

### Version Behavior
- **On exact tag**: Package version = tag version (e.g., `0.1.2`)
- **After tag**: Package version = development version (e.g., `0.1.2.post3.dev0+hash`)
- **Dirty working directory**: Additional "dirty" suffix
- **Build artifacts**: Always use exact tag version

### Troubleshooting Version Issues
The `task version:set` command now automatically handles version synchronization and building.

If you need manual cleanup: `task version:reset`

This clears all build caches and forces complete reinstallation.

## Type Checking

Le projet utilise deux outils de vérification de types en parallèle :

### MyPy (Production)
- **Configuration**: `[tool.mypy]` dans `pyproject.toml`
- **Mode strict** activé avec toutes les options de vérification stricte
- **Commande**: `task typecheck:mypy` ou `uv run mypy mecapy`
- **Utilisation**: Outil principal pour la CI/CD et validation de production

### Ty (Expérimental)
- **Configuration**: `[tool.ty]` dans `pyproject.toml`
- **Type checker** extrêmement rapide d'Astral (créateurs de ruff)
- **Status**: Pré-version (alpha), non prêt pour la production
- **Commande**: `task typecheck:ty` ou `uv run ty check mecapy`
- **Avantages**:
  - Performance exceptionnelle (beaucoup plus rapide que mypy)
  - Configuration stricte équivalente à mypy
  - Intégration native avec l'écosystème Astral

### Configuration Équivalente
Les deux outils sont configurés avec des paramètres équivalents :

**MyPy (référence)**:
- `python_version = "3.13"`
- `disallow_untyped_defs = true`
- `disallow_any_generics = true`
- `warn_return_any = true`
- Mode strict complet

**Ty (équivalent)**:
- `python-version = "3.13"`
- `error-on-warning = true`
- `possibly-unresolved-reference = "error"`
- Configuration strict avec overrides pour les sources

### Utilisation Recommandée
- **Développement local**: Utiliser `ty` pour des vérifications rapides
- **CI/CD**: Continuer avec `mypy` pour la stabilité
- **Commande globale**: `task check` exécute les deux outils
- **Transition progressive**: Observer les différences entre les deux outils