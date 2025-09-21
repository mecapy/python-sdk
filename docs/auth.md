# Authentification

## Principe d'authentification (Authorization Code + PKCE)

### Lancement du flow

Quand tu tapes 'mecapy auth login', l’outil génère un PKCE code_verifier/code_challenge.
Il démarre un mini serveur HTTP local (souvent sur localhost:8085 ou un port dispo).

### Ouverture du navigateur

Il ouvre ton navigateur par défaut vers l’URL d’auth de Keycloak (ex. https://accounts.google.com/o/oauth2/auth?...)
Cette URL contient redirect_uri=http://localhost:8085/ et le code_challenge.

### Authentification utilisateur

Tu te connectes avec ton compte Keycloak.
Keycloak valide et redirige ton navigateur vers http://localhost:8085/callback/?code=XYZ...
Pour cela, il faut que la configuration keycloak autorise le redirect_uri : http://localhost:*/callback
On utilise une wildcar sur le port pour la flexibilité si de nombreux ports sont bloqués.

### Capture du code par le mini serveur

Le mini serveur de gcloud reçoit la requête HTTP avec le code.
Il répond une petite page HTML genre "You may now close this window".
Puis il s’arrête immédiatement.

### Échange du code contre un token

Le CLI envoie le code + code_verifier à Keycloak → récupère un access token + refresh token.
L’access token émis par Keycloak est généralement un JWT signé.
La signature garantit que le token n’a pas été falsifié.

### Stockage local

Les tokens sont sauvegardés dans ~/.config/mecapy/credentials.db.
À chaque commande gcloud ..., le SDK réutilise le refresh token pour régénérer un access token si besoin.

### Envoie du token à l'API

L’API doit connaître la clé publique de Keycloak qui a signé le token.

Vérifications typiques dans l’API:
- Signature → validée avec la clé publique Keycloak.
- Issuer (iss) → doit correspondre à ton realm Keycloak.
- Audience (aud) → doit correspondre à l’API cible (souvent un client “API” dans Keycloak).
- Expiration (exp) → vérifier que le token n’est pas expiré.

