# security-starter-demo-cookie

Application Spring Boot minimale utilisant `zrouga.spring:security-starter:2.0.0`
en **mode `cookie`** (Stateful Session Cookies) : le access token est posé en
cookie `zrouga_access` (`HttpOnly`, `Path=/`) et le refresh token en cookie
`zrouga_refresh` (`HttpOnly`, `Path=/api/auth`) — le front n'a jamais à manipuler
les jetons. Comptes en mémoire, inscription, connexion, rotation de refresh token
et un endpoint protégé `/api/me`.

> Pour le mode **Stateless JWT** en header (`auth-mode: header`), voir
> [`../demo-jwt`](../demo-jwt).

## Prérequis

- Java 21
- Le starter installé localement : depuis la racine du repo, `.\mvnw.cmd install`
  (sinon la dépendance `2.0.0` est résolue depuis GitHub Packages)

## Lancer

```bash
cd examples/demo-cookie
mvnw spring-boot:run
```

> Écoute sur le port **8081** (demo-jwt reste sur 8080) : les deux démos peuvent
> tourner en parallèle.

## Compte de démonstration

| Champ | Valeur |
|---|---|
| E-mail | `demo@demo.com` |
| Mot de passe | `Demo1234!` |

## Flux d'appels (curl)

```bash
base=http://localhost:8081

# 1. Connexion : les deux cookies HttpOnly sont posés (le corps JSON contient
#    aussi les tokens, pratique pour les tests)
curl -i -c cookies.txt -X POST "$base/api/auth/signin" \
  -H 'Content-Type: application/json' \
  -d '{"email":"demo@demo.com","password":"Demo1234!"}'

# 2. Endpoint protégé : la cookie d'access token est envoyée automatiquement
curl -b cookies.txt "$base/api/me"

# 3. Rotation du refresh token : corps vide, la cookie zrouga_refresh (Path=/api/auth)
#    est lue automatiquement — les deux cookies sont réémis (rotation invisible)
curl -i -b cookies.txt -c cookies.txt -X POST "$base/api/auth/refreshtoken" \
  -H 'Content-Type: application/json' -d '{}'

# 4. Déconnexion : les deux cookies sont vidés (Max-Age=0)
curl -i -b cookies.txt -c cookies.txt -X POST "$base/api/auth/signout"

# 5. Après déconnexion, l'ancienne cookie ne donne plus rien d'utile
#    (le refresh token est révoqué ; l'access JWT reste valide jusqu'à expiration)
curl -i -b cookies.txt "$base/api/me"
```

## Flux d'appels (PowerShell)

```powershell
$base = "http://localhost:8081"
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

# 1. Connexion : les cookies (zrouga_access, zrouga_refresh) sont dans $session
Invoke-RestMethod -Method Post -Uri "$base/api/auth/signin" -WebSession $session `
    -ContentType "application/json" `
    -Body '{"email":"demo@demo.com","password":"Demo1234!"}'

# 2. Endpoint protégé
Invoke-RestMethod -Uri "$base/api/me" -WebSession $session

# 3. Rotation : corps vide, cookie lue automatiquement, cookies réémis
Invoke-RestMethod -Method Post -Uri "$base/api/auth/refreshtoken" -WebSession $session `
    -ContentType "application/json" -Body '{}'

# 4. Déconnexion : cookies vidés
Invoke-RestMethod -Method Post -Uri "$base/api/auth/signout" -WebSession $session
```

## Côté front (SPA)

- Axios/fetch : `withCredentials: true` sur toutes les requêtes ;
- CORS : `allowCredentials(true)` avec des **origines explicites** (jamais `*`) ;
- aucun stockage de token en JS nécessaire : le navigateur gère les cookies
  (`HttpOnly` = invisibles au JavaScript, protection XSS).

## Réinitialisation SMTP (optionnelle)

Par défaut désactivée. Pour l'activer :

1. Lancer un SMTP local (ex. Mailpit sur `localhost:1025`)
2. Décommenter `reset-enabled`, `reset-base-url`, `reset-email-from` et
   `spring.mail.*` dans `src/main/resources/application.yml`

Flux : `POST /api/auth/forgot-password` → e-mail contenant le lien
`{reset-base-url}?token=...` → `POST /api/auth/reset-password`.
En mode cookie, un reset réussi vide aussi les cookies d'auth (tous les refresh
tokens du compte sont révoqués).
