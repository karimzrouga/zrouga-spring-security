# zrouga-spring-security-starter

Starter Spring Security **générique et autonome** : JWT (HS512), refresh token, abstraction `AuthUser` / `AuthUserProvider`, rôles illimités. Réutilisable dans n'importe quel projet Spring Boot 4 / Java 21 — aucune dépendance à polyvalence ni à aucune entité métier.

- Coordonnées : `zrouga.spring:security-starter:1.0.0`
- Auto-configuré via `AutoConfiguration.imports` : rien à importer, l'ajout de la dépendance suffit.

## 1. Dépendance (projet consommateur)

```xml
<repositories>
    <repository>
        <id>github</id>
        <url>https://maven.pkg.github.com/karimzrouga/zrouga-spring-security</url>
    </repository>
</repositories>

<dependencies>
    <dependency>
        <groupId>zrouga.spring</groupId>
        <artifactId>security-starter</artifactId>
        <version>1.0.0</version>
    </dependency>
</dependencies>
```

GitHub Packages exige une authentification même en lecture : ajoutez dans `~/.m2/settings.xml`

```xml
<servers>
    <server>
        <id>github</id>
        <username>VOTRE_GITHUB_LOGIN</username>
        <password>VOTRE_PAT_READ_PACKAGES</password>
    </server>
</servers>
```

## 2. Configuration

```yaml
zrouga:
  security:
    jwt-secret: <base64, >= 64 caractères alphanumériques>   # obligatoire
    jwt-expiration-ms: 1800000                               # défaut : 30 min
    jwt-refresh-expiration-ms: 86400000                      # défaut : 24 h
    public-paths:                                            # défaut : /api/auth/**
      - /api/auth/**
```

Le secret doit être encodable en Base64 standard (lettres/chiffres uniquement, longueur multiple de 4).

## 3. Implémenter le pont vers votre projet (obligatoire)

Vous implémentez `AuthUser` (vos utilisateurs) et `AuthUserProvider` (leur accès) :

```java
@Component
public class MonAuthUserProvider implements AuthUserProvider {

    private final UtilisateurRepository repository; // votre entité / votre table

    @Override
    public Optional<AuthUser> findByEmail(String email) {
        return repository.findByEmail(email).map(this::toAuthUser);
    }

    @Override
    public Optional<AuthUser> findById(Long id) {
        return repository.findById(id).map(this::toAuthUser);
    }

    private AuthUser toAuthUser(Utilisateur u) {
        return new AuthUser() {
            public Long getId() { return u.getId(); }
            public String getEmail() { return u.getEmail(); }
            public String getPassword() { return u.getPassword(); }        // hash
            public List<String> getRoles() { return List.of(u.getRole().name()); } // illimités
            public Boolean getStatus() { return u.getActif(); }
        };
    }
}
```

Sans bean `AuthUserProvider`, le démarrage échoue avec un message explicite.

## 4. Endpoints exposés (parité avec polyvalence)

| Méthode | Chemin | Corps / réponse |
|---|---|---|
| POST | `/api/auth/signin` | `{email, password}` → `{token, type: "Bearer", refreshToken}` |
| POST | `/api/auth/refreshtoken` | `{refreshToken}` → `{accessToken, refreshToken, tokenType: "Bearer"}` |
| POST | `/api/auth/signout` | (Bearer) → `{message}` |

Erreurs :

- 401 (JWT absent/ invalident, mauvais mot de passe) : `{status, error, message, path}`
- 403 refresh token (inconnu / expiré) : `{statusCode, timestamp, message, description}`

Tout le reste de l'API est `authenticated()` sauf `public-paths`.

## 5. Claims du JWT (HS512)

`sub` = email, `id`, `email`, `roles` (liste illimitée), `status` (Boolean), `exp`.
Signature : `zrouga.security.jwt-secret`.

## 6. Refresh token

- **Projet avec JPA** (`spring-boot-starter-data-jpa` présent) : table `refreshtoken` créée automatiquement (`user_id`, `token` unique, `expiryDate`), store `JpaRefreshTokenStore`.
- **Sans JPA** : store en mémoire (`InMemoryRefreshTokenStore`).
- Personnalisable : déclarez votre propre bean `RefreshTokenStore` — les auto-configs reculent.

## 7. Personnalisation

- `SecurityFilterChain` : définissez votre propre bean (le filtre par défaut est désactivé).
- `PasswordEncoder` : définissez votre propre bean (défaut `BCryptPasswordEncoder`).
- Exclusion complète : `spring.autoconfigure.exclude=zrouga.spring.security.autoconfigure.ZrougaSecurityAutoConfiguration`
- CORS : à définir côté projet hôte (aucune origine codée en dur côté starter).

## 8. Build / publication (mainteneur)

```powershell
.\mvnw.cmd test
$env:GITHUB_TOKEN = gh auth token   # scope write:packages
.\mvnw.cmd deploy                   # → GitHub Packages
```

Repository source : https://github.com/karimzrouga/zrouga-spring-security
