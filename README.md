# zrouga-spring-security-starter

Starter Spring Security **générique et autonome** : JWT (HS512), refresh token avec rotation, rate-limiting sur la connexion, verrouillage de compte et politique de mot de passe (**optionnels**), abstraction `AuthUser` / `AuthUserProvider`, rôles illimités, inscription, réinitialisation du mot de passe par e-mail SMTP (**optionnelle**). Réutilisable dans n'importe quel projet Spring Boot 4 / Java 21 .

- Coordonnées : `zrouga.spring:security-starter:2.0.0` (voir `CHANGELOG.md` pour les ruptures)
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
    <!-- spring-boot-starter-web est OPTIONNEL dans le starter : à déclarer ici -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>zrouga.spring</groupId>
        <artifactId>security-starter</artifactId>
        <version>2.0.0</version>
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
    auth-mode: header                                # défaut : header | cookie (§11)
    cookie-secure: false                             # drapeau Secure des cookies d'auth (true en HTTPS)
    cookie-same-site: Lax                            # SameSite des cookies : Lax | Strict | None
    public-paths:                                    # défaut : /api/auth/**
      - /api/auth/**
    rate-limit-max-attempts: 5                       # défaut : 5 échecs puis 429
    rate-limit-window-ms: 900000                     # défaut : fenêtre de 15 min
    lockout-enabled: false                           # défaut : verrouillage de compte DÉSACTIVÉ
    lockout-max-attempts: 5                          # défaut : 5 échecs puis 423
    lockout-duration-ms: 900000                      # défaut : verrou de 15 min
    password-policy-enabled: false                   # défaut : politique de mot de passe DÉSACTIVÉE
    password-min-length: 8                           # défaut : longueur minimale
    password-require-uppercase: true                 # défaut : majuscule exigée
    password-require-lowercase: true                 # défaut : minuscule exigée
    password-require-digit: true                     # défaut : chiffre exigé
    password-require-special: true                   # défaut : caractère spécial exigé
    password-history-count: 3                        # défaut : 3 anciens mots de passe refusés
    trust-forwarded-for: false                       # défaut : X-Forwarded-For ignoré (true derrière un proxy)
    cleanup-enabled: false                           # défaut : purge des refresh tokens expirés désactivée
    cleanup-fixed-delay-ms: 3600000                  # défaut : purge toutes les 1 h
    reset-enabled: false                             # défaut : réinitialisation SMTP DÉSACTIVÉE
    reset-base-url: ""                               # obligatoire si reset-enabled=true (URL front)
    reset-token-expiration-ms: 900000                # défaut : jeton valable 15 min
    reset-email-from: ""                             # défaut : spring.mail.username
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
| POST | `/api/auth/forgot-password` | `{email}` → `{message}` (**200**, toujours identique — si `reset-enabled`) |
| POST | `/api/auth/reset-password` | `{token, password}` → `{message}` (**200** — si `reset-enabled`) |
| POST | `/api/auth/refreshtoken` | `{refreshToken}` → `{accessToken, refreshToken, tokenType: "Bearer"}` (**refreshToken tourné**) |
| POST | `/api/auth/signout` | (Bearer) → `{message}` |

En mode `cookie` (§11) : `/signin` et `/refreshtoken` posent en plus les cookies d'auth
(réponse JSON identique), `/refreshtoken` accepte un corps vide (la cookie
`zrouga_refresh` est lue automatiquement) et `/signout` vide les cookies.

### Erreurs — format unifié

Toutes les erreurs du starter (400, 401, 403, 409, 423, 429, 501) ont la forme :

```json
{ "status": 403, "error": "Forbidden", "message": "...", "path": "/api/auth/refreshtoken", "timestamp": "2026-11-22T12:00:00Z" }
```

| Cas | Statut |
|---|---|
| JWT absent / invalide / compte inactif / mauvais mot de passe | 401 |
| Refresh token inconnu, expiré ou déjà tourné | 403 |
| E-mail déjà utilisé lors d'une inscription | 409 |
| Jeton de réinitialisation invalide, expiré ou déjà utilisé | 400 |
| Trop de tentatives de connexion (`rate-limit-max-attempts`) | 429 |
| Compte verrouillé après N échecs (`lockout-max-attempts`) — code `account_locked` | 423 |
| Mot de passe refusé par la politique (`password-policy-enabled`) — code `weak_password` | 400 |
| Corps de requête invalide (validation `@Valid`) | 400 |
| Inscription sans bean `AuthUserCreator` déclaré | 501 |
| Réinitialisation désactivée (`reset-enabled=false`) | 501 |

Le message d'erreur ne contient **jamais** la valeur du refresh token.

Tout le reste de l'API est `authenticated()` sauf `public-paths`.

## 5. Inscription — `POST /api/auth/signup`

Corps : `{"email": "...", "password": "..."}` — mot de passe de **8 à 128 caractères**, e-mail valide.
Réponse `201` : `{"message": "User registered successfully!"}` puis connectez-vous via `/signin`.
Avec `password-policy-enabled=true`, le mot de passe doit en plus satisfaire la politique (§13) → `400 weak_password`.

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
| Mot de passe refusé par la politique (§13) — `weak_password` | 400 |
| Trop d'inscriptions ratées pour le même e-mail (rate-limit) | 429 |

## 6. Réinitialisation du mot de passe (optionnelle — SMTP)

**Désactivée par défaut** — activez-la uniquement si vous en avez besoin :

```yaml
zrouga:
  security:
    reset-enabled: true                              # active la fonctionnalité
    reset-base-url: https://mon-front.test/reset     # obligatoire (page front)
    reset-token-expiration-ms: 900000                # défaut : jeton 15 min
    reset-email-from: no-reply@mon-projet.test       # défaut : spring.mail.username
spring:
  mail:                                              # SMTP — dépendance spring-boot-starter-mail
    host: smtp.example.test
    port: 587
    username: user@mon-projet.test
    password: ***
```

Au démarrage avec `reset-enabled=true`, le starter **échoue avec un message explicite** si
`reset-base-url`, le bean `AuthUserPasswordUpdater` ou le `JavaMailSender` (`spring.mail.*`)
manque. Sans `reset-enabled`, aucune exigence — les deux endpoints répondent 501.

### SPI obligatoire — `AuthUserPasswordUpdater`

```java
@Component
public class MonPasswordUpdater implements AuthUserPasswordUpdater {

    private final UtilisateurRepository repository; // votre entité / votre table

    @Override
    public void updatePassword(String email, String encodedPassword) {
        Utilisateur u = repository.findByEmail(email).orElseThrow();
        u.setPassword(encodedPassword);   // hash BCrypt déjà produit par le starter
        repository.save(u);
    }
}
```

### Flux

| Étape | Appel | Réponse |
|---|---|---|
| 1. Demande | `POST /api/auth/forgot-password` `{email}` | **200** toujours identique (anti-énumération) — l'e-mail part seulement si le compte existe |
| 2. Lien | e-mail SMTP : `{reset-base-url}?token=…` | jeton aléatoire 256 bits, valable 15 min, **usage unique** |
| 3. Nouveau mot de passe | `POST /api/auth/reset-password` `{token, password}` | **200** — hash enregistré + **tous les refresh tokens du compte révoqués** |

- **Rate-limit** : 5 demandes / 15 min par e-mail (compte connu ou non — pas d'énumération par 429).
- Jeton invalide, expiré ou déjà utilisé → **400** `Invalid or expired reset token.` (même message partout).
- **Politique de mot de passe** (§13, si `password-policy-enabled=true`) : le nouveau mot de passe est
  validé **avant** la consommation du jeton — un refus (`400 weak_password`) laisse le jeton utilisable.
- **SMTP par défaut** (`SmtpPasswordResetEmailSender`) ; personnalisez avec votre propre bean
  `PasswordResetEmailSender` (SendGrid, API métier, console de dev…) — `spring.mail.*` n'est alors
  pas requis.
- Stockage en mémoire par défaut ; déclarez `PasswordResetTokenStore` pour une persistance
  distribuée (Redis, table SQL).

## 7. Autorisation par rôle — API non publiques

Modèle par défaut : `public-paths` (défaut `/api/auth/**`) → `permitAll()` ; **tout le reste** →
`authenticated()` (JWT valide + compte actif). Pour exiger **en plus** un rôle sur une route non
publique, deux approches :

### Déclarer un endpoint PUBLIC ou PRIVÉ

**Public** (sans jeton) = déclaré dans `zrouga.security.public-paths` — **privé** = tout le reste, automatiquement.

```yaml
zrouga:
  security:
    public-paths:                # ← seuls ces chemins sont PUBLICS
      - /api/auth/**             # défaut : signup, signin, refreshtoken, signout
      - /api/public/**           # ex : ressources ouvertes
      - /health                  # ex : chemin exact
```

| Déclaration | Endpoint privé (défaut) | Endpoint public | Endpoint privé + rôle |
|---|---|---|---|
| **Où** | rien à faire — hors `public-paths` | `public-paths` (YAML) | `@PreAuthorize` ou `SecurityFilterChain` |
| **Exigence** | JWT valide + compte actif → sinon **401** | aucune | rôle absent → **403** |
| **Exemple** | `GET /api/hello` | `POST /api/auth/signup` | `GET /api/admin/stats` |

- Motifs Spring : `*` = un segment, `**` = plusieurs segments, sans joker = chemin exact.
- La liste YAML **remplace** le défaut : répétez `/api/auth/**` si vous ajoutez d'autres chemins.
- Attention : plus une liste est large (`/**`), plus d'endpoints échappent à l'authentification —
  déclarez strictement ce qui doit l'être.

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

## 8. Claims du JWT (HS512)

`sub` = email, `id`, `email`, `roles` (liste illimitée, valeurs brutes), `status` (Boolean), `exp`.
Signature : `zrouga.security.jwt-secret`.

Côté Spring Security, les autorités sont construites avec le préfixe standard `ROLE_` :
utilisez `@PreAuthorize("hasRole('ADMIN')")` (et non `hasAuthority('ADMIN')`) — détails §7.

## 9. Comptes désactivés (status)

- `AuthUser.getStatus()` vaut `false` → **connexion refusée** (401) ;
- un JWT existant d'un compte désactivé est **refusé à chaque requête** (le claim `status` est vérifié) ;
- `null` = pas d'information → compte actif.

## 10. Refresh token

- **Hash en base** : la base ne stocke que le **hash SHA-256** du jeton (`TokenHashing`) — un vol de base ne donne aucun jeton utilisable.
- **Rotation** : chaque `/refreshtoken` révoque l'ancien jeton et en émet un nouveau (opération CAS atomique, sûre en concurrence).
- **Réutilisation = vol détecté** : présenter un jeton déjà tourné révoque **toute la famille** de l'utilisateur et répond 403 (`refresh_token_rejected`).
- **Connexion** : un nouvel `signin` révoque tous les refresh tokens précédents de l'utilisateur (politique mono-session).
- **Projet avec JPA** (`spring-boot-starter-data-jpa` présent) : table `refreshtoken` créée automatiquement (`user_id`, `token` (hash unique), `expiry_date`, `revoked`, index), store `JpaRefreshTokenStore`.
- **Sans JPA** : store en mémoire (`InMemoryRefreshTokenStore`).
- **Purge des expirés** : optionnelle — `zrouga.security.cleanup-enabled=true` active une purge périodique (`cleanup-fixed-delay-ms`), également des jetons de réinitialisation (§6).
- Personnalisable : déclarez votre propre bean `RefreshTokenStore` — les auto-configs reculent.

## 11. Modes d'authentification

Deux modes, commutables via `zrouga.security.auth-mode` — une valeur inconnue fait
**échouer le démarrage** (pas de repli silencieux) :

| Mode | Access token | Refresh token | Nature |
|---|---|---|---|
| `header` (défaut) | en-tête `Authorization: Bearer <JWT>` | corps JSON de `POST /refreshtoken` | **Stateless JWTs** |
| `cookie` | cookie `zrouga_access` (`HttpOnly`, `Path=/`) | cookie `zrouga_refresh` (`HttpOnly`, `Path=/api/auth`) | **Stateful Session Cookies** |

### Mode `header` (défaut)

Comportement historique : le front stocke les deux tokens et renvoie le refresh
dans le corps de `/refreshtoken`.

### Mode `cookie`

- `/signin` et `/refreshtoken` **posent** les deux cookies (réémis à chaque rotation,
  donc invisible côté navigateur) ; le corps JSON reste identique — les tokens y
  figurent aussi, les tests curl restent possibles.
- Le filtre lit le header `Authorization` **puis** la cookie ; `/refreshtoken` lit le
  corps **puis** la cookie : les deux transports coexistent sur la même application.
- `/signout` et un `/reset-password` **réussi** vident les deux cookies (`Max-Age=0`) ;
  un échec laisse la session intacte.
- Flags : `cookie-secure` (défaut `false` pour le dev HTTP → `true` en production
  HTTPS) et `cookie-same-site` (défaut `Lax` ; `None` impose `cookie-secure: true`
  si le front est sur un autre domaine).
- **Front (SPA)** : `withCredentials: true` + CORS `allowCredentials(true)` avec des
  **origines explicites** (jamais `*`).
- **CSRF** : CSRF reste désactivé dans la chaîne — les cookies `SameSite=Lax`
  (défaut) ne sont pas envoyés en cross-site ; préférez `Strict` si front et API
  partagent un domaine.
- La session Spring reste `STATELESS` (aucun `HttpSession`) : les cookies ne
  transportent que les tokens.

```yaml
zrouga:
  security:
    auth-mode: cookie            # défaut : header
    cookie-secure: false         # true en production (HTTPS)
    cookie-same-site: Lax        # Lax | Strict | None
```

Voir les démos : `examples/demo-jwt` (header) et `examples/demo-cookie` (cookie).

## 12. Rate-limiting (anti-bruteforce)

5 tentatives échouées par e-mail puis 15 minutes de blocage (429), par défaut — réglable via
`rate-limit-max-attempts` / `rate-limit-window-ms`. Une connexion réussie remet le compteur à zéro.

- **Clés** : `signin|signup|forgot:email:<email>` et `signin|signup|forgot:ip:<ip>` — le quota IP est **×10** le quota e-mail.
- **Vérification atomique** : la tentative est **réservée** avant l'authentification (une échec consomme le quota) ; `429` porte le code `rate_limit_exceeded`.
- **Derrière un proxy** : `zrouga.security.trust-forwarded-for: true` fait lire `X-Forwarded-For` (défaut `false` : IP réelle).
- Personnalisable : déclarez votre propre bean `LoginRateLimiter` (base de données, Redis, …).

### Verrouillage de compte (optionnel)

`zrouga.security.lockout-enabled: true` ajoute un verrou **par compte**, en plus du rate-limit :

- après `lockout-max-attempts` échecs consécutifs (défaut 5), le compte répond **423** `account_locked`
  pendant `lockout-duration-ms` (défaut 15 min) — **y compris avec le bon mot de passe** ;
- une connexion réussie ou l'expiration du verrou remettent le compteur à zéro (après expiration, on repart de zéro) ;
- un compte **inconnu** se verrouille de la même manière : aucun observable différent = pas d'énumération d'e-mails ;
- les tentatives sur un compte verrouillé restent soumises au rate-limit (le verrou ne protège pas contre le flood) ;
- complémentaire au rate-limit : rate-limit protège **par e-mail/IP** (fenêtre glissante), verrouillage **par compte** (durée fixe) ;
- par défaut en mémoire (perdu au redémarrage, plafond de 10 000 comptes suivis) — déclarez votre propre bean
  `AccountLockoutService` pour persister (Redis, base de données, déverrouillage admin via `reset(email)`).

## 13. Politique de mot de passe (optionnelle)

`zrouga.security.password-policy-enabled: true` valide le mot de passe sur `/signup` et `/reset-password` →
**400** `weak_password`, avec la liste de **toutes** les règles manquantes dans le message.

- **Règles** : `password-min-length` (défaut 8), `password-require-uppercase`, `password-require-lowercase`,
  `password-require-digit`, `password-require-special` (défauts tous `true` ; le spécial = caractère non
  alphanumérique non espace).
- **Anti-réutilisation** : `password-history-count` (défaut 3, `0` = seul le mot de passe courant est vérifié) —
  à la réinitialisation, refus du mot de passe **courant** et des **précédents** (`400 weak_password`).
- **Jeton préservé** : sur `/reset-password`, la politique est validée **avant** la consommation du jeton —
  un refus laisse le jeton utilisable pour une nouvelle tentative.
- La validation `@Size` du DTO (8 à 128 caractères) reste active même sans politique.
- Historique en mémoire par défaut (perdu au redémarrage ; le hash du mot de passe courant, lui, est toujours
  vérifié) — déclarez votre propre bean `PasswordHistoryStore` pour le persister.
- Personnalisable : déclarez votre propre bean `PasswordPolicy` (dictionnaire de mots de passe, NIST SP 800-63B, …).

## 14. Personnalisation

Tous les beans suivants sont surchargeables — déclarez le vôtre et celui du starter est remplacé :

| Bean | Défaut du starter |
|---|---|
| `SecurityFilterChain` | chaîne stateless JWT |
| `PasswordEncoder` | `BCryptPasswordEncoder` |
| `AuthenticationManager` | via `AuthenticationConfiguration` |
| `AuthenticationProvider` | `DaoAuthenticationProvider` |
| `UserDetailsService` | lit via `AuthUserProvider` |
| `JwtUtils` | HS512 + secret `zrouga.security.jwt-secret` |
| `AuthTokenFilter` | filtre Bearer (et cookie `zrouga_access` en mode `cookie`) |
| `RefreshTokenService` | jetons d'expiration configurable |
| `RefreshTokenStore` | JPA si disponible, sinon mémoire |
| `LoginRateLimiter` | en mémoire (fenêtre par e-mail) |
| `AccountLockoutService` | en mémoire (verrouillage de compte) |
| `PasswordPolicy` | longueur + complexité (`password-*`) |
| `PasswordHistoryStore` | en mémoire (anti-réutilisation) |
| `PasswordResetTokenStore` | en mémoire (jetons de réinitialisation) |
| `PasswordResetEmailSender` | SMTP (`spring.mail.*`), seulement si `reset-enabled=true` |
| `AuthUserPasswordUpdater` | SPI projet hôte (requis si `reset-enabled=true`) |
| `AuthService`, `AuthResource`, `AuthEntryPointJwt`, `TokenControllerAdvice`, `PasswordResetService` | implémentations par défaut |

- Exclusion complète : `spring.autoconfigure.exclude=zrouga.spring.security.autoconfigure.ZrougaSecurityAutoConfiguration`
- `AuthUserCreator` : SPI fournie par le projet hôte (voir §5) — sans elle, `/signup` répond 501.
- CORS : à définir côté projet hôte (aucune origine codée en dur côté starter).
- `@CrossOrigin` supprimé : configurez le CORS via votre `CorsConfigurationSource` / `WebMvcConfigurer`.
- **Image native GraalVM** : hints fournis (`ZrougaRuntimeHints` + `META-INF/spring/aot.factories`) pour les DTO réfléchis.
- **Erreurs** : `AuthException` + sous-exceptions portent un `code()` machine ; `TokenControllerAdvice` ne traite que les exceptions du starter (déclarez le vôtre pour vos contrôleurs).

## 15. Build / publication (mainteneur)

```powershell
.\mvnw.cmd verify          # tests + jacoco + jar + sources + javadoc
$env:GITHUB_TOKEN = gh auth token   # scope write:packages
.\mvnw.cmd deploy          # → GitHub Packages
```

- **CI GitHub Actions** (`.github/workflows/ci.yml`) : `mvnw verify` à chaque push/PR ; publication automatique sur tag `v*`.
- **Release** : merge sur `main`, tag `v2.0.0` → la CI publie la version.
- **Exemple d'application** : `examples/demo-jwt/` (Stateless JWT en header) et `examples/demo-cookie/` (Stateful Session Cookies) — le starter doit être `mvnw installé` localement avant de les builder.
- **Couverture** : rapport JaCoCo dans `target/site/jacoco/` (seuil verrouillé : ≥ 80 % instructions, ≥ 55 % branches).
- **Métadonnées IDE** : autocomplétion et descriptions des propriétés `zrouga.security.*` (configuration-processor).

Repository source : https://github.com/karimzrouga/zrouga-spring-security
