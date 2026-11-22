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

Pour activer l'inscription (`/api/auth/signup`), déclarez en plus un bean `AuthUserCreator` — voir §5.

## 4. Endpoints exposés

| Méthode | Chemin | Corps / réponse |
|---|---|---|
| POST | `/api/auth/signup` | `{email, password}` → `{message}` (**201**) |
| POST | `/api/auth/signin` | `{email, password}` → `{token, type: "Bearer", refreshToken}` |
| POST | `/api/auth/refreshtoken` | `{refreshToken}` → `{accessToken, refreshToken, tokenType: "Bearer"}` (**refreshToken tourné**) |
| POST | `/api/auth/signout` | (Bearer) → `{message}` |

### Erreurs — format unifié

Toutes les erreurs du starter (400, 401, 403, 409, 429, 501) ont la forme :

```json
{ "status": 403, "error": "Forbidden", "message": "...", "path": "/api/auth/refreshtoken", "timestamp": "2026-11-22T12:00:00Z" }
```

| Cas | Statut |
|---|---|
| JWT absent / invalide / compte inactif / mauvais mot de passe | 401 |
| Refresh token inconnu, expiré ou déjà tourné | 403 |
| E-mail déjà utilisé lors d'une inscription | 409 |
| Trop de tentatives de connexion (`rate-limit-max-attempts`) | 429 |
| Corps de requête invalide (validation `@Valid`) | 400 |
| Inscription sans bean `AuthUserCreator` déclaré | 501 |

Le message d'erreur ne contient **jamais** la valeur du refresh token.

Tout le reste de l'API est `authenticated()` sauf `public-paths`.

## 5. Inscription — `POST /api/auth/signup`

Corps : `{"email": "...", "password": "..."}` — mot de passe de **8 à 128 caractères**, e-mail valide.
Réponse `201` : `{"message": "User registered successfully!"}` puis connectez-vous via `/signin`.

L'inscription est **publique** (couverte par `public-paths` = `/api/auth/**`). Pour l'activer, déclarez un bean `AuthUserCreator` — c'est votre projet qui crée réellement l'utilisateur :

```java
@Component
public class MonAuthUserCreator implements AuthUserCreator {

    private final UtilisateurRepository repository; // votre entité / votre table

    @Override
    public void create(String email, String encodedPassword) {
        Utilisateur u = new Utilisateur();
        u.setEmail(email);
        u.setPassword(encodedPassword);   // hash BCrypt déjà produit par le starter
        u.setRole(Role.USER);             // ← les rôles sont DÉCIDÉS ICI
        u.setActif(true);
        repository.save(u);
    }
}
```

> **Les rôles ne viennent jamais du client** : le corps de signup ne contient que `email` et `password`.
> C'est `AuthUserCreator` qui attribue le rôle (rôle par défaut, validation manuelle, …) — sinon un
> nouvel utilisateur pourrait s'auto-élever en `ADMIN`.

| Cas | Statut |
|---|---|
| Inscription réussie | 201 |
| E-mail déjà utilisé | 409 |
| Aucun bean `AuthUserCreator` déclaré | 501 (message : « declarez un bean AuthUserCreator… ») |
| Corps invalide (e-mail, mot de passe < 8 caractères) | 400 |
| Trop d'inscriptions ratées pour le même e-mail (rate-limit) | 429 |

## 6. Autorisation par rôle — API non publiques

Modèle par défaut : `public-paths` (défaut `/api/auth/**`) → `permitAll()` ; **tout le reste** →
`authenticated()` (JWT valide + compte actif). Pour exiger **en plus** un rôle sur une route non
publique, deux approches :

### a) Par annotation (recommandé — `@EnableMethodSecurity` déjà actif)

```java
@RestController
@RequestMapping("/api/admin")
public class AdminResource {

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/stats")
    public Stats stats() { ... }                 // 403 si rôle ADMIN absent

    @PreAuthorize("hasAnyRole('ADMIN', 'AQP')")
    @GetMapping("/rapports")
    public List<Rapport> rapports() { ... }      // 403 si ni ADMIN ni AQP
}
```

Sur une classe entière : placez `@PreAuthorize("hasRole('ADMIN')")` au-dessus de `public class …`.

### b) Par route (déclarez votre propre `SecurityFilterChain`)

Votre bean remplace celui du starter (`@ConditionalOnMissingBean`) :

```java
@Bean
SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.csrf(AbstractHttpConfigurer::disable)
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/auth/**").permitAll()            // public
            .requestMatchers("/api/admin/**").hasRole("ADMIN")      // rôle exigé
            .requestMatchers("/api/controle/**").hasAnyRole("ADMIN", "AQP")
            .anyRequest().authenticated())                           // le reste : jeton valide
        .exceptionHandling(e -> e.authenticationEntryPoint(unauthorizedHandler))
        .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    return http.build();
}
```

### Bonnes pratiques

- **`hasRole('X')` sans préfixe** : les claims JWT portent `ADMIN` (sans `ROLE_`) et le préfixe est
  ajouté automatiquement à la construction des autorités — écrivez `hasRole("ADMIN")`, **jamais**
  `hasRole("ROLE_ADMIN")` (sinon 403 permanent).
- Sans jeton → **401** ; jeton valide mais rôle absent → **403**.
- La règle s'applique à **chaque requête côté serveur** : le front ne fait que de l'affichage.
- Les rôles viennent de `AuthUser.getRoles()` : illimités, valeurs brutes (`"ADMIN"`, `"AQP"`, …).
- L'ordre des `requestMatchers` compte : les règles spécifiques avant `anyRequest().authenticated()`.

## 7. Claims du JWT (HS512)

`sub` = email, `id`, `email`, `roles` (liste illimitée, valeurs brutes), `status` (Boolean), `exp`.
Signature : `zrouga.security.jwt-secret`.

Côté Spring Security, les autorités sont construites avec le préfixe standard `ROLE_` :
utilisez `@PreAuthorize("hasRole('ADMIN')")` (et non `hasAuthority('ADMIN')`) — détails §6.

## 8. Comptes désactivés (status)

- `AuthUser.getStatus()` vaut `false` → **connexion refusée** (401) ;
- un JWT existant d'un compte désactivé est **refusé à chaque requête** (le claim `status` est vérifié) ;
- `null` = pas d'information → compte actif.

## 9. Refresh token

- **Rotation** : chaque `/refreshtoken` révoque l'ancien jeton et en émet un nouveau. Toute réutilisation d'un jeton déjà tourné répond 403 (détection de vol).
- **Connexion** : un nouvel `signin` révoque tous les refresh tokens précédents de l'utilisateur (politique mono-session).
- **Projet avec JPA** (`spring-boot-starter-data-jpa` présent) : table `refreshtoken` créée automatiquement (`user_id`, `token` unique, `expiryDate`), store `JpaRefreshTokenStore`.
- **Sans JPA** : store en mémoire (`InMemoryRefreshTokenStore`).
- **Purge des expirés** : optionnelle — `zrouga.security.cleanup-enabled=true` active une purge périodique (`cleanup-fixed-delay-ms`).
- Personnalisable : déclarez votre propre bean `RefreshTokenStore` — les auto-configs reculent.

## 10. Rate-limiting (anti-bruteforce)

5 tentatives échouées par e-mail puis 15 minutes de blocage (429), par défaut — réglable via
`rate-limit-max-attempts` / `rate-limit-window-ms`. Une connexion réussie remet le compteur à zéro.
Le même compteur protège l'inscription (clé `signup:<email>`).
Personnalisable : déclarez votre propre bean `LoginRateLimiter` (base de données, Redis, …).

## 11. Personnalisation

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
- `AuthUserCreator` : SPI fournie par le projet hôte (voir §5) — sans elle, `/signup` répond 501.
- CORS : à définir côté projet hôte (aucune origine codée en dur côté starter).
- `@CrossOrigin` supprimé : configurez le CORS via votre `CorsConfigurationSource` / `WebMvcConfigurer`.

## 12. Build / publication (mainteneur)

```powershell
.\mvnw.cmd verify          # tests + jacoco + jar + sources + javadoc
$env:GITHUB_TOKEN = gh auth token   # scope write:packages
.\mvnw.cmd deploy          # → GitHub Packages
```

- **CI GitHub Actions** (`.github/workflows/ci.yml`) : `mvnw verify` à chaque push/PR ; publication automatique sur tag `v*`.
- **Couverture** : rapport JaCoCo dans `target/site/jacoco/`.
- **Métadonnées IDE** : autocomplétion et descriptions des propriétés `zrouga.security.*` (configuration-processor).

Repository source : https://github.com/karimzrouga/zrouga-spring-security
