# zrouga-spring-security-starter

[English](README.md) | **Français**

[![CI](https://github.com/karimzrouga/zrouga-spring-security/actions/workflows/ci.yml/badge.svg)](https://github.com/karimzrouga/zrouga-spring-security/actions/workflows/ci.yml)
[![CodeQL](https://github.com/karimzrouga/zrouga-spring-security/actions/workflows/codeql.yml/badge.svg)](https://github.com/karimzrouga/zrouga-spring-security/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/karimzrouga/zrouga-spring-security)](https://github.com/karimzrouga/zrouga-spring-security/releases)
[![Java 21](https://img.shields.io/badge/Java-21-blue)](https://openjdk.org/projects/jdk/21/)
[![Spring Boot 4.1](https://img.shields.io/badge/Spring%20Boot-4.1-6DB33F)](https://spring.io/projects/spring-boot)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Starter Spring Security **générique et autonome** : JWT (HS512), refresh token avec rotation, rate-limiting sur la connexion, verrouillage de compte et politique de mot de passe (**optionnels**), abstraction `AuthUser` / `AuthUserProvider`, rôles illimités, inscription, réinitialisation du mot de passe par e-mail SMTP (**optionnelle**), **vérification d'e-mail** et **double authentification TOTP** (**optionnelles**), **événements, métriques Micrometer et health indicator**. Réutilisable dans n'importe quel projet Spring Boot 4 / Java 21.

- Coordonnées : `zrouga.spring:security-starter:2.2.0` (voir `CHANGELOG.md` pour les ruptures)
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
        <version>2.2.0</version>
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
    revocation-enabled: false                        # défaut : révocation jti DÉSACTIVÉE (§10)
    concurrent-sessions-enabled: false               # défaut : mono-session (un signin purge les jetons)
    refresh-binding-enabled: false                   # défaut : binding IP/UA DÉSACTIVÉ (§10)
    trust-forwarded-for: false                       # défaut : X-Forwarded-For ignoré (true derrière un proxy)
    cleanup-enabled: false                           # défaut : purge des refresh tokens expirés désactivée
    cleanup-fixed-delay-ms: 3600000                  # défaut : purge toutes les 1 h
    reset-enabled: false                             # défaut : réinitialisation SMTP DÉSACTIVÉE
    reset-base-url: ""                               # obligatoire si reset-enabled=true (URL front)
    reset-token-expiration-ms: 900000                # défaut : jeton valable 15 min
    reset-email-from: ""                             # défaut : spring.mail.username
    email-verification-enabled: false                # défaut : vérification d'e-mail DÉSACTIVÉE (§16)
    email-verification-base-url: ""                  # obligatoire si enabled (URL front)
    email-verification-token-ttl-ms: 86400000        # défaut : jeton valable 24 h
    email-verification-from: ""                      # défaut : spring.mail.username
    two-factor-enabled: false                        # défaut : 2FA TOTP DÉSACTIVÉE (§17)
    two-factor-issuer: zrouga                        # défaut : "zrouga" (dans otpauth://)
    two-factor-challenge-ttl-ms: 300000              # défaut : challenge valable 5 min
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
| POST | `/api/auth/signin` | `{email, password}` → `{token, type: "Bearer", refreshToken}` (ou challenge 2FA, §17) |
| POST | `/api/auth/forgot-password` | `{email}` → `{message}` (**200**, toujours identique — si `reset-enabled`) |
| POST | `/api/auth/reset-password` | `{token, password}` → `{message}` (**200** — si `reset-enabled`) |
| POST | `/api/auth/refreshtoken` | `{refreshToken}` → `{accessToken, refreshToken, tokenType: "Bearer"}` (**refreshToken tourné**) |
| POST | `/api/auth/signout` | (Bearer) → `{message}` |
| POST | `/api/auth/verify-email` | `{token}` → `{message}` (**si `email-verification-enabled`**, §16) |
| POST | `/api/auth/resend-verification` | `{email}` → `{message}` (**toujours identique** — anti-énumération) |
| POST | `/api/auth/2fa/setup` | (Bearer) → `{secret, otpauthUri}` (§17) |
| POST | `/api/auth/2fa/enable` | (Bearer) `{code}` → `{message}` (§17) |
| POST | `/api/auth/2fa/disable` | (Bearer) `{code}` → `{message}` (§17) |
| POST | `/api/auth/2fa/verify` | `{twoFactorToken, code}` → tokens complets (§17) |

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
| Refresh token dont le binding IP/UA ne correspond plus (`refresh-binding-enabled`) | 403 |
| E-mail déjà utilisé lors d'une inscription | 409 |
| Jeton de réinitialisation invalide, expiré ou déjà utilisé | 400 |
| Jeton de vérification d'e-mail invalide, expiré ou déjà utilisé | 400 `verification_token_invalid` |
| Trop de tentatives de connexion (`rate-limit-max-attempts`) | 429 |
| Compte verrouillé après N échecs (`lockout-max-attempts`) — code `account_locked` | 423 |
| Mot de passe refusé par la politique (`password-policy-enabled`) — code `weak_password` | 400 |
| Corps de requête invalide (validation `@Valid`) | 400 |
| Inscription sans bean `AuthUserCreator` déclaré | 501 `signup_not_supported` |
| Réinitialisation désactivée (`reset-enabled=false`) | 501 `reset_not_supported` |
| Vérification d'e-mail désactivée (`email-verification-enabled=false`) | 501 `verification_not_supported` |
| 2FA désactivée (`two-factor-enabled=false`) sur `/2fa/*` | 501 `two_factor_not_supported` |
| Code TOTP invalide | 400 `invalid_two_factor_code` |
| Challenge 2FA manquant ou expiré (`/2fa/verify`) | 401 `two_factor_token_invalid` |

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
      - /api/auth/**             # défaut : signup, signin, refreshtoken, signout, 2fa, verify-email
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

`sub` = email, `id`, `email`, `roles` (liste illimitée, valeurs brutes), `status` (Boolean), `exp`,
`jti` (identifiant unique — sert à la révocation, §10).
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
- **Connexion** : par défaut (`concurrent-sessions-enabled=false`), un nouvel `signin` révoque tous les
  refresh tokens précédents de l'utilisateur (politique mono-session) ; `true` autorise plusieurs sessions simultanées.
- **Révocation access token** (`revocation-enabled=true`) : le `jti` du JWT est enregistré à la
  déconnexion (`/signout`) et rejeté à chaque requête tant que le jeton n'est pas expiré —
  plafond de 10 000 jetons suivis en mémoire (store surchargeable : `AccessTokenRevocationStore`).
- **Binding IP/UA** (`refresh-binding-enabled=true`) : chaque refresh token mémorise l'IP et le
  `User-Agent` de son émission ; une rotation depuis une autre IP/UA répond 403 (le jeton reste
  valide sans binding si le binding a été désactivé entre-temps).
- **Projet avec JPA** (`spring-boot-starter-data-jpa` présent) : table `refreshtoken` créée
  automatiquement (`user_id`, `token` (hash unique), `expiry_date`, `revoked`, `ip`, `user_agent`,
  index), store `JpaRefreshTokenStore`.
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

- **Clés** : `signin|signup|forgot|verification:email:<email>` et `…:ip:<ip>` — le quota IP est **×10** le quota e-mail.
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
| `AccessTokenRevocationStore` | en mémoire (révocation `jti`, plafond 10 000) |
| `LoginRateLimiter` | en mémoire (fenêtre par e-mail) |
| `AccountLockoutService` | en mémoire (verrouillage de compte) |
| `PasswordPolicy` | longueur + complexité (`password-*`) |
| `PasswordHistoryStore` | en mémoire (anti-réutilisation) |
| `PasswordResetTokenStore` | en mémoire (jetons de réinitialisation) |
| `PasswordResetEmailSender` | SMTP (`spring.mail.*`), seulement si `reset-enabled=true` |
| `AuthUserPasswordUpdater` | SPI projet hôte (requis si `reset-enabled=true`) |
| `EmailVerificationTokenStore` | en mémoire (jetons de vérification, §16) |
| `EmailVerificationEmailSender` | SMTP asynchrone (`spring.mail.*`), seulement si `email-verification-enabled=true` |
| `AuthUserEmailVerifier` | SPI projet hôte (requis si `email-verification-enabled=true`) |
| `TwoFactorSecretStore` | en mémoire (secrets TOTP, §17) |
| `AuthService`, `AuthResource`, `AuthEntryPointJwt`, `TokenControllerAdvice`, `PasswordResetService`, `EmailVerificationService` | implémentations par défaut |

- Exclusion complète : `spring.autoconfigure.exclude=zrouga.spring.security.autoconfigure.ZrougaSecurityAutoConfiguration`
- `AuthUserCreator` : SPI fournie par le projet hôte (voir §5) — sans elle, `/signup` répond 501.
- CORS : à définir côté projet hôte (aucune origine codée en dur côté starter).
- `@CrossOrigin` supprimé : configurez le CORS via votre `CorsConfigurationSource` / `WebMvcConfigurer`.
- **Image native GraalVM** : hints fournis (`ZrougaRuntimeHints` + `META-INF/spring/aot.factories`) pour les DTO réfléchis.
- **Erreurs** : `AuthException` + sous-exceptions portent un `code()` machine ; `TokenControllerAdvice` ne traite que les exceptions du starter (déclarez le vôtre pour vos contrôleurs).
- **Événements** : tous les événements de §18 sont publiés via `ApplicationEventPublisher` —
  écoutez-les avec `@EventListener` dans votre projet.

## 15. Build / publication (mainteneur)

```powershell
.\mvnw.cmd verify          # tests + jacoco + japicmp + jar + sources + javadoc
$env:GITHUB_TOKEN = gh auth token   # scope write:packages
.\mvnw.cmd deploy          # → GitHub Packages
```

- **CI GitHub Actions** (`.github/workflows/ci.yml`) : construction de la release
  précédente puis `mvnw verify` (tests + JaCoCo + **japicmp**) à chaque push/PR ;
  publication sur tag `v*` + **release GitHub créée avec notes automatiques**.
- **CodeQL** (`.github/workflows/codeql.yml`) : analyse de sécurité à chaque push/PR + hebdomadaire.
- **Dependabot** (`.github/dependabot.yml`) : mises à jour hebdomadaires Maven (racine + démos) et GitHub Actions.
- **Release** : processus complet dans [`RELEASING.md`](RELEASING.md) (bump version,
  `japicmp.oldVersion`, CHANGELOG, tag `v2.2.0` → CI publie et génère les notes).
- **Exemple d'application** : `examples/demo-jwt/` (Stateless JWT en header) et `examples/demo-cookie/` (Stateful Session Cookies) — le starter doit être `mvnw installé` localement avant de les builder.
- **Couverture** : rapport JaCoCo dans `target/site/jacoco/` (seuil verrouillé : ≥ 80 % instructions, ≥ 55 % branches).
- **Compatibilité binaire** : rapport japicmp dans `target/japicmp/japicmp.md` — toute
  rupture binaire casse le build (shims `@Deprecated` ou exclusions ciblées).
- **Métadonnées IDE** : autocomplétion et descriptions des propriétés `zrouga.security.*` (configuration-processor).

Repository source : https://github.com/karimzrouga/zrouga-spring-security

## 16. Vérification d'e-mail (optionnelle)

**Désactivée par défaut.** À la première activation : déclarez le SPI `AuthUserEmailVerifier`
(le démarrage échoue avec un message explicite s'il manque), `email-verification-base-url`
et un `JavaMailSender` (ou votre propre `EmailVerificationEmailSender`).

```yaml
zrouga:
  security:
    email-verification-enabled: true
    email-verification-base-url: https://mon-front.test/verify   # page front
    email-verification-token-ttl-ms: 86400000                    # 24 h
    email-verification-from: no-reply@mon-projet.test            # défaut : spring.mail.username
```

```java
@Component
public class MonEmailVerifier implements AuthUserEmailVerifier {

    private final UtilisateurRepository repository;

    @Override
    public void verifyEmail(String email) {
        repository.findByEmail(email).ifPresent(u -> u.setEmailVerifie(true));
    }
}
```

### Flux

| Étape | Appel | Réponse |
|---|---|---|
| 1. Inscription | `POST /signup` → événement `SignUpEvent` | jeton 256 bits émis (TTL 24 h) + e-mail envoyé **en asynchrone** : `{email-verification-base-url}?token=…` |
| 2. Vérification | `POST /verify-email` `{token}` | **200** — jeton consommé (usage unique) + `AuthUserEmailVerifier.verifyEmail(email)` appelé |
| 3. Renvoi | `POST /resend-verification` `{email}` | **200** toujours identique (anti-énumération) — nouvel émission si le compte existe |

- **Rate-limit** : par e-mail, par IP, et par IP sur les jetons de vérification (clés `verification:*`).
- Jeton invalide, expiré ou déjà utilisé → **400** `verification_token_invalid` (même message partout).
- Sans `email-verification-enabled`, les endpoints répondent **501** `verification_not_supported`.
- Stockage en mémoire par défaut ; déclarez `EmailVerificationTokenStore` pour une persistance distribuée.
- L'envoi SMTP par défaut est **asynchrone** (le signup n'attend pas le réseau).

## 17. Double authentification — TOTP (optionnelle)

**Désactivée par défaut.** Compatible tout authenticator TOTP (Google Authenticator, Authy, 1Password…) :
RFC 6238, SHA-1, 6 chiffres, pas de 30 s, fenêtre ±1.

```yaml
zrouga:
  security:
    two-factor-enabled: true
    two-factor-issuer: mon-projet          # défaut : "zrouga"
    two-factor-challenge-ttl-ms: 300000    # défaut : challenge valable 5 min
```

### Flux

| Étape | Appel | Réponse |
|---|---|---|
| 1. Activation | `POST /2fa/setup` (Bearer) | **200** `{secret, otpauthUri}` — saisir le secret manuellement ou encoder `otpauthUri` en QR côté front |
| 2. Confirmation | `POST /2fa/enable` (Bearer) `{code}` | **200** — code TOTP valide exigé ; 2FA active pour le compte |
| 3. Connexion | `POST /signin` (2FA active) | **200** `{twoFactorRequired: true, twoFactorToken}` — **aucun token émis** avant vérification |
| 4. Vérification | `POST /2fa/verify` `{twoFactorToken, code}` | **200** tokens complets (+ cookies en mode `cookie`) |
| 5. Désactivation | `POST /2fa/disable` (Bearer) `{code}` | **200** — preuve par le code courant exigée |

- Le challenge `twoFactorToken` est un JWT limité (claim `2fa`), valable `two-factor-challenge-ttl-ms` (5 min par défaut).
- Secrets stockés via `TwoFactorSecretStore` (en mémoire par défaut — déclarez le vôtre pour
  persister : table SQL, Redis).
- Sans `two-factor-enabled`, les endpoints `/2fa/*` répondent **501** `two_factor_not_supported`.
- Code expiré ou inexact → **400** `invalid_two_factor_code` ; challenge manquant/expiré → **401** `two_factor_token_invalid`.
- Les deux transports (header / cookie) fonctionnent avec le challenge.

## 18. Observabilité — événements, métriques, health

### Événements Spring

Publiés via `ApplicationEventPublisher` — écoutez-les avec `@EventListener` :

| Événement | Publié quand |
|---|---|
| `SignInEvent` | connexion réussie |
| `SignInFailedEvent` | connexion échouée (mot de passe, rate-limit, verrou, compte inactif) |
| `SignUpEvent` | inscription créée |
| `SignOutEvent` | déconnexion (`/signout`) |
| `TokenRefreshedEvent` | rotation de refresh token réussie |
| `LockoutEvent` | compte verrouillé (`lockout-enabled`) |
| `PasswordResetEvent` | mot de passe réinitialisé |
| `EmailVerifiedEvent` | e-mail vérifié (§16) |

### Métriques Micrometer

Nécessite `spring-boot-starter-actuator` (optionnel dans le starter) sur le classpath du projet
consommateur. Compteurs exposés via n'importe quel `MeterRegistry` :

| Compteur | Tags |
|---|---|
| `zrouga.security.signin` | `outcome=success\|failure` |
| `zrouga.security.signup` | — |
| `zrouga.security.signout` | — |
| `zrouga.security.token.refresh` | — |
| `zrouga.security.account.lockout` | — |
| `zrouga.security.password.reset` | — |
| `zrouga.security.email.verified` | — |

### Health indicator

Avec l'actuator exposé (`/actuator/health`), le composant **`zrougaSecurity`** résume la
**configuration** (toujours `UP` — il ne dépend d'aucun service externe) :

```json
{
  "status": "UP",
  "components": {
    "zrougaSecurity": {
      "status": "UP",
      "details": {
        "authMode": "header", "revocation": false, "concurrentSessions": false,
        "refreshBinding": false, "emailVerification": false, "twoFactor": false,
        "lockout": false, "passwordPolicy": false, "passwordReset": false,
        "signup": true, "status": "UP"
      }
    }
  }
}
```

## 19. FAQ / Dépannage

**`401` sur chaque requête même avec un token valide**
→ Secret invalide (Base64 ≥ 64 octets), en-tête `Authorization: Bearer <JWT>` manquant, ou
`AuthUser.getStatus()` = `false` (compte désactivé, §9). Vérifiez aussi l'horloge (`exp`).

**`403 refresh_token_rejected` après un refresh**
→ Réutilisation d'un jeton déjà tourné : la **famille entière** est révoquée (§10). Le front doit
stocker le `refreshToken` renvoyé par chaque `/refreshtoken`. Avec `refresh-binding-enabled=true`,
un changement d'IP ou de `User-Agent` produit aussi ce 403.

**Les cookies ne sont pas posés (mode `cookie`)**
→ `cookie-secure: true` exige HTTPS ; `cookie-same-site: None` impose `cookie-secure: true` ;
front sur un autre domaine → `SameSite=None` + CORS `allowCredentials(true)` avec origines
explicites. En curl, pensez `-c`/`-b` pour le jar de cookies.

**`501 verification_not_supported` / `501 two_factor_not_supported`**
→ Fonctionnalité désactivée : activez `email-verification-enabled` (§16) ou
`two-factor-enabled` (§17) — et vérifiez les prérequis (SPI, base URL, SMTP).

**`501 signup_not_supported` ou message « declarez un bean AuthUserCreator »**
→ Déclarez le SPI du projet hôte (§3/§5) : `AuthUserCreator`, `AuthUserPasswordUpdater`
(reset), `AuthUserEmailVerifier` (vérification e-mail).

**Démarrage en échec : « aucun bean … déclaré » ou secret invalide**
→ Messages explicites au démarrage : manque un SPI requis par une option activée, ou
`jwt-secret` n'est pas un Base64 valide ≥ 64 octets (§2).

**`429 rate_limit_exceeded`**
→ Fenêtre de 5 tentatives / 15 min (§12). Derrière un proxy : `trust-forwarded-for: true`.
Rate-limit élevé : déclarez votre propre `LoginRateLimiter`.

**`423 account_locked`**
→ `lockout-enabled` : 5 échecs → verrou 15 min (§12). Déblocage : attendre, ou bean
`AccountLockoutService` personnalisé avec `reset(email)`.

**Aucune métrique `zrouga.security.*`**
→ Ajoutez `spring-boot-starter-actuator` au projet consommateur et exposez un endpoint
(`management.endpoints.web.exposure.include`) ; le registre Micrometer de Spring Boot fait le reste.

**`/actuator/health` ne montre pas `zrougaSecurity`**
→ Même cause : actuator absent du classpath ou endpoint health non exposé (§18).

**Le test `JpaRefreshTokenStorePostgresTest` est « skipped »**
→ Normal sans Docker : le test Testcontainers se skippe (`disabledWithoutDocker`) et tourne
en CI. Installez Docker pour l'exécuter en local.

**japicmp ne tourne pas (« ignore missing old version »)**
→ L'ancienne version (`japicmp.oldVersion`) n'est pas dans votre `~/.m2` : la CI la construit
depuis le tag `vX.Y.Z` ; en local, installez-la une fois depuis le tag (voir `RELEASING.md`).
