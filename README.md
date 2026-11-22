# zrouga-spring-security-starter

Starter Spring Security **générique et autonome** : JWT (HS512), refresh token avec rotation, rate-limiting sur la connexion, abstraction `AuthUser` / `AuthUserProvider`, rôles illimités. Réutilisable dans n'importe quel projet Spring Boot 4 / Java 21 .

- Coordonnées : `zrouga.spring:security-starter:1.1.0`
- Auto-configuré via `AutoConfiguration.imports` : rien à importer, l'ajout de la dépendance suffit.
- Licence : MIT.

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
        <version>1.1.0</version>
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
    jwt-secret: <base64, >= 64 octets décodés>      # obligatoire
    jwt-expiration-ms: 1800000                       # défaut : 30 min
    jwt-refresh-expiration-ms: 86400000              # défaut : 24 h
    public-paths:                                    # défaut : /api/auth/**
      - /api/auth/**
    rate-limit-max-attempts: 5                       # défaut : 5 échecs puis 429
    rate-limit-window-ms: 900000                     # défaut : fenêtre de 15 min
    cleanup-enabled: false                           # défaut : purge des refresh tokens expirés désactivée
    cleanup-fixed-delay-ms: 3600000                  # défaut : purge toutes les 1 h
```

Le secret doit être un **Base64 standard valide** (A-Z, a-z, 0-9, +, /, =) décodant à **au moins 64 octets (512 bits)** — exigence HS512, vérifiée au démarrage. Génération : `openssl rand -base64 64`.

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
            public Boolean getStatus() { return u.getActif(); }            // false = compte désactivé
        };
    }
}
```

Sans bean `AuthUserProvider`, le démarrage échoue avec un message explicite.

## 4. Endpoints exposés

| Méthode | Chemin | Corps / réponse |
|---|---|---|
| POST | `/api/auth/signin` | `{email, password}` → `{token, type: "Bearer", refreshToken}` |
| POST | `/api/auth/refreshtoken` | `{refreshToken}` → `{accessToken, refreshToken, tokenType: "Bearer"}` (**refreshToken tourné**) |
| POST | `/api/auth/signout` | (Bearer) → `{message}` |

### Erreurs — format unifié

Toutes les erreurs du starter (400, 401, 403, 429) ont la forme :

```json
{ "status": 403, "error": "Forbidden", "message": "...", "path": "/api/auth/refreshtoken", "timestamp": "2026-11-22T12:00:00Z" }
```

| Cas | Statut |
|---|---|
| JWT absent / invalide / compte inactif / mauvais mot de passe | 401 |
| Refresh token inconnu, expiré ou déjà tourné | 403 |
| Trop de tentatives de connexion (`rate-limit-max-attempts`) | 429 |
| Corps de requête invalide (validation `@Valid`) | 400 |

Le message d'erreur ne contient **jamais** la valeur du refresh token.

Tout le reste de l'API est `authenticated()` sauf `public-paths`.

## 5. Claims du JWT (HS512)

`sub` = email, `id`, `email`, `roles` (liste illimitée, valeurs brutes), `status` (Boolean), `exp`.
Signature : `zrouga.security.jwt-secret`.

Côté Spring Security, les autorités sont construites avec le préfixe standard `ROLE_` :
utilisez `@PreAuthorize("hasRole('ADMIN')")` (et non `hasAuthority('ADMIN')`).

## 6. Comptes désactivés (status)

- `AuthUser.getStatus()` vaut `false` → **connexion refusée** (401) ;
- un JWT existant d'un compte désactivé est **refusé à chaque requête** (le claim `status` est vérifié) ;
- `null` = pas d'information → compte actif.

## 7. Refresh token

- **Rotation** : chaque `/refreshtoken` révoque l'ancien jeton et en émet un nouveau. Toute réutilisation d'un jeton déjà tourné répond 403 (détection de vol).
- **Connexion** : un nouvel `signin` révoque tous les refresh tokens précédents de l'utilisateur (politique mono-session).
- **Projet avec JPA** (`spring-boot-starter-data-jpa` présent) : table `refreshtoken` créée automatiquement (`user_id`, `token` unique, `expiryDate`), store `JpaRefreshTokenStore`.
- **Sans JPA** : store en mémoire (`InMemoryRefreshTokenStore`).
- **Purge des expirés** : optionnelle — `zrouga.security.cleanup-enabled=true` active une purge périodique (`cleanup-fixed-delay-ms`).
- Personnalisable : déclarez votre propre bean `RefreshTokenStore` — les auto-configs reculent.

## 8. Rate-limiting (anti-bruteforce)

5 tentatives échouées par e-mail puis 15 minutes de blocage (429), par défaut — réglable via
`rate-limit-max-attempts` / `rate-limit-window-ms`. Une connexion réussie remet le compteur à zéro.
Personnalisable : déclarez votre propre bean `LoginRateLimiter` (base de données, Redis, …).

## 9. Personnalisation

Tous les beans suivants sont surchargeables — déclarez le vôtre et celui du starter est remplacé :

| Bean | Défaut du starter |
|---|---|
| `SecurityFilterChain` | chaîne stateless JWT |
| `PasswordEncoder` | `BCryptPasswordEncoder` |
| `AuthenticationManager` | via `AuthenticationConfiguration` |
| `AuthenticationProvider` | `DaoAuthenticationProvider` |
| `UserDetailsService` | lit via `AuthUserProvider` |
| `JwtUtils` | HS512 + secret `zrouga.security.jwt-secret` |
| `AuthTokenFilter` | filtre Bearer |
| `RefreshTokenService` | jetons d'expiration configurable |
| `RefreshTokenStore` | JPA si disponible, sinon mémoire |
| `LoginRateLimiter` | en mémoire (fenêtre par e-mail) |
| `AuthService`, `AuthResource`, `AuthEntryPointJwt`, `TokenControllerAdvice` | implémentations par défaut |

- Exclusion complète : `spring.autoconfigure.exclude=zrouga.spring.security.autoconfigure.ZrougaSecurityAutoConfiguration`
- CORS : à définir côté projet hôte (aucune origine codée en dur côté starter).
- `@CrossOrigin` supprimé : configurez le CORS via votre `CorsConfigurationSource` / `WebMvcConfigurer`.

## 10. Build / publication (mainteneur)

```powershell
.\mvnw.cmd verify          # tests + jacoco + jar + sources + javadoc
$env:GITHUB_TOKEN = gh auth token   # scope write:packages
.\mvnw.cmd deploy          # → GitHub Packages
```

- **CI GitHub Actions** (`.github/workflows/ci.yml`) : `mvnw verify` à chaque push/PR ; publication automatique sur tag `v*`.
- **Couverture** : rapport JaCoCo dans `target/site/jacoco/`.
- **Métadonnées IDE** : autocomplétion et descriptions des propriétés `zrouga.security.*` (configuration-processor).

Repository source : https://github.com/karimzrouga/zrouga-spring-security
