# security-starter-demo

Application Spring Boot minimale utilisant `zrouga.spring:security-starter:2.0.0` :
comptes en mémoire, inscription, connexion JWT, rotation de refresh token et un
endpoint protégé `/api/me`.

## Prérequis

- Java 21
- Le starter installé localement : depuis la racine du repo, `.\mvnw.cmd install`
  (sinon la dépendance `2.0.0` est résolue depuis GitHub Packages)

## Lancer

```bash
cd examples/demo
mvnw spring-boot:run
```

> `spring-boot-starter-web` doit être déclaré par l'application : il est
> **optionnel** dans le starter depuis la 2.0.0.

## Compte de démonstration

| Champ | Valeur |
|---|---|
| E-mail | `demo@demo.com` |
| Mot de passe | `Demo1234!` |

## Flux d'appels (PowerShell)

```powershell
$base = "http://localhost:8080"

# 1. Connexion
$login = Invoke-RestMethod -Method Post -Uri "$base/api/auth/signin" `
    -ContentType "application/json" `
    -Body '{"email":"demo@demo.com","password":"Demo1234!"}'
$login.accessToken   # JWT
$login.refreshToken

# 2. Endpoint protégé
Invoke-RestMethod -Uri "$base/api/me" -Headers @{ Authorization = "Bearer $($login.accessToken)" }

# 3. Rotation du refresh token (l'ancien devient invalide)
Invoke-RestMethod -Method Post -Uri "$base/api/auth/refreshtoken" `
    -ContentType "application/json" `
    -Body (@{ refreshToken = $login.refreshToken } | ConvertTo-Json)

# 4. Inscription
Invoke-RestMethod -Method Post -Uri "$base/api/auth/signup" `
    -ContentType "application/json" `
    -Body '{"email":"nouveau@test.com","password":"MotDePasse123"}'
```

## Réinitialisation SMTP (optionnelle)

Par défaut désactivée. Pour l'activer :

1. Lancer un SMTP local (ex. Mailpit sur `localhost:1025`)
2. Décommenter `reset-enabled`, `reset-base-url`, `reset-email-from` et
   `spring.mail.*` dans `src/main/resources/application.yml`

Flux : `POST /api/auth/forgot-password` → e-mail contenant le lien
`{reset-base-url}?token=...` → `POST /api/auth/reset-password`.
