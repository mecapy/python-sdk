# Authentification MecaPy SDK

## Table des matières

1. [Principe d'authentification (Authorization Code + PKCE)](#principe-dauthentification-authorization-code--pkce)
2. [Authentification par tokens longue durée](#authentification-par-tokens-longue-durée)
3. [Comparaison avec PyGithub](#comparaison-avec-pygithub)
4. [Configuration Keycloak](#configuration-keycloak)

## Principe d'authentification (Authorization Code + PKCE)

### Lancement du flow

Quand tu tapes 'mecapy auth login', l'outil génère un PKCE code_verifier/code_challenge.
Il démarre un mini serveur HTTP local (souvent sur localhost:8085 ou un port dispo).

### Ouverture du navigateur

Il ouvre ton navigateur par défaut vers l'URL d'auth de Keycloak (ex. https://accounts.google.com/o/oauth2/auth?...)
Cette URL contient redirect_uri=http://localhost:8085/ et le code_challenge.

### Authentification utilisateur

Tu te connectes avec ton compte Keycloak.
Keycloak valide et redirige ton navigateur vers http://localhost:8085/callback/?code=XYZ...
Pour cela, il faut que la configuration keycloak autorise le redirect_uri : http://localhost:*/callback
On utilise une wildcar sur le port pour la flexibilité si de nombreux ports sont bloqués.

### Capture du code par le mini serveur

Le mini serveur de gcloud reçoit la requête HTTP avec le code.
Il répond une petite page HTML genre "You may now close this window".
Puis il s'arrête immédiatement.

### Échange du code contre un token

Le CLI envoie le code + code_verifier à Keycloak → récupère un access token + refresh token.
L'access token émis par Keycloak est généralement un JWT signé.
La signature garantit que le token n'a pas été falsifié.

### Stockage local

Les tokens sont sauvegardés dans ~/.config/mecapy/credentials.db.
À chaque commande gcloud ..., le SDK réutilise le refresh token pour régénérer un access token si besoin.

### Envoie du token à l'API

L'API doit connaître la clé publique de Keycloak qui a signé le token.

Vérifications typiques dans l'API:
- Signature → validée avec la clé publique Keycloak.
- Issuer (iss) → doit correspondre à ton realm Keycloak.
- Audience (aud) → doit correspondre à l'API cible (souvent un client "API" dans Keycloak).
- Expiration (exp) → vérifier que le token n'est pas expiré.

## Authentification par tokens longue durée

### 1. Service Account avec Client Credentials

**C'est la méthode recommandée pour l'authentification machine-to-machine** comme votre SDK.

#### Configuration dans Keycloak Admin Console :

1. **Créer un client dédié** :
   ```
   Client ID: mecapy-sdk-service
   Client Type: OpenID Connect
   Access Type: confidential
   ```

2. **Activer Service Account** :
   - Dans les paramètres du client : `Service Accounts Enabled: ON`
   - Dans l'onglet "Service Account Roles", assigner les rôles nécessaires

3. **Configurer la durée de vie des tokens** :
   - Aller dans `Realm Settings > Tokens`
   - Modifier `Access Token Lifespan` (par défaut 5 minutes)
   - Pour des tokens longue durée : augmenter à 24h, 7 jours, etc.

#### Obtenir un token :

```bash
curl -X POST \
  "https://auth.mecapy.com/realms/mecapy/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=mecapy-sdk-service" \
  -d "client_secret=YOUR_CLIENT_SECRET"
```

### 2. Offline Tokens (Refresh Tokens persistants)

Pour des applications qui ont besoin d'accès long terme sans re-authentification :

#### Configuration :
1. **Dans le client** : `Offline Access Enabled: ON`
2. **Demander le scope offline_access** lors de l'authentification initiale

#### Utilisation :
```bash
# Authentification initiale avec scope offline_access
curl -X POST \
  "https://auth.mecapy.com/realms/mecapy/protocol/openid-connect/token" \
  -d "grant_type=authorization_code" \
  -d "client_id=mecapy-api-public" \
  -d "code=AUTHORIZATION_CODE" \
  -d "scope=openid offline_access"

# Le refresh_token retourné n'expire jamais (sauf révocation)
```

### 3. Configuration des durées de vie

#### Dans Realm Settings > Tokens :

```
Access Token Lifespan: 24h (au lieu de 5m par défaut)
Refresh Token Max Reuse: 0 (tokens réutilisables)
SSO Session Idle: 30 jours
SSO Session Max: 30 jours
Offline Session Idle: jamais (pour offline tokens)
```

#### Par client (plus granulaire) :
Dans `Client Settings > Advanced Settings` :
```
Access Token Lifespan: Override realm (ex: 7 jours)
Client Session Idle: 30 jours
Client Session Max: 30 jours
```

### 4. Implémentation dans votre SDK

Pour ajouter le support des tokens dans votre MecaPy SDK :

```python
# mecapy/auth.py
class TokenAuth(AuthBase):
    """Token-based authentication using long-lived service account tokens."""

    def __init__(self, token: str):
        self.token = token

    def get_access_token(self) -> str:
        return self.token

    def __call__(self, request):
        request.headers['Authorization'] = f'Bearer {self.token}'
        return request

# mecapy/client.py
class MecaPyClient:
    @classmethod
    def from_token(cls, token: str, api_url: str = None) -> "MecaPyClient":
        """Create client with service account token."""
        auth = TokenAuth(token)
        return cls(api_url or "https://api.mecapy.com", auth=auth)
```

### 5. Sécurité et bonnes pratiques

#### Recommandations :

1. **Service Accounts pour CI/CD** : Utilisez des clients dédiés avec des rôles limités
2. **Rotation des secrets** : Changez périodiquement les `client_secret`
3. **Monitoring** : Surveillez l'utilisation des tokens dans Keycloak Admin Events
4. **Principe du moindre privilège** : N'accordez que les rôles strictement nécessaires
5. **Stockage sécurisé** : Utilisez des variables d'environnement ou des gestionnaires de secrets

#### Configuration recommandée pour votre SDK :

```yaml
# Pour les utilisateurs finaux (durée courte)
Access Token Lifespan: 1h
Refresh Token: 24h

# Pour les service accounts (CI/CD)
Access Token Lifespan: 24h-7j selon le besoin
Client credentials flow uniquement
```

## Comparaison avec PyGithub

### Architecture PyGithub vs MecaPy SDK

| Aspect | PyGithub | MecaPy SDK |
|--------|----------|------------|
| **Backend** | GitHub API REST/GraphQL | FastAPI + Keycloak OAuth2/OIDC |
| **Auth Strategy** | Multiple auth types (7 methods) | OAuth2 + PKCE, Service Accounts |
| **Token Management** | Static tokens, JWT Apps | Dynamic tokens with refresh |
| **Security** | API tokens, JWT signing | OIDC compliance, PKCE |
| **User Experience** | Simple token auth | Browser-based OAuth flow |

### Méthodes d'authentification PyGithub :

1. **Auth.Token** - Personal Access Token (simple)
2. **Auth.Login** - Username/password (deprecated)
3. **Auth.AppAuth** - GitHub App avec JWT
4. **Auth.AppAuthToken** - Installation token
5. **Auth.AppInstallationAuth** - App installation
6. **Auth.NetrcAuth** - .netrc file
7. **Auth.DefaultAuth** - Multiple sources

### Adaptation pour MecaPy SDK :

```python
# Équivalents proposés pour MecaPy
from mecapy import Auth

# 1. Token simple (service account)
auth = Auth.Token("your-long-lived-token")

# 2. OAuth2 interactif (existant)
auth = Auth.OAuth2.from_env()

# 3. Service account avec credentials
auth = Auth.ServiceAccount(client_id="...", client_secret="...")

# 4. Multi-source (credentials > env > keyring)
auth = Auth.Default()
```

## Configuration Keycloak

Cette approche vous permettra d'implémenter `Auth.Token` similaire à PyGithub tout en maintenant la sécurité OAuth2/OIDC de Keycloak.
