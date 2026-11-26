# zrouga-spring-security-starter

**English** | [Français](README.fr.md)

[![CI](https://github.com/karimzrouga/zrouga-spring-security/actions/workflows/ci.yml/badge.svg)](https://github.com/karimzrouga/zrouga-spring-security/actions/workflows/ci.yml)
[![CodeQL](https://github.com/karimzrouga/zrouga-spring-security/actions/workflows/codeql.yml/badge.svg)](https://github.com/karimzrouga/zrouga-spring-security/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/karimzrouga/zrouga-spring-security)](https://github.com/karimzrouga/zrouga-spring-security/releases)
[![Java 21](https://img.shields.io/badge/Java-21-blue)](https://openjdk.org/projects/jdk/21/)
[![Spring Boot 4.1](https://img.shields.io/badge/Spring%20Boot-4.1-6DB33F)](https://spring.io/projects/spring-boot)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Generic, self-contained Spring Security starter: JWT (HS512), refresh token with rotation, sign-in rate limiting, account lockout and password policy (**optional**), `AuthUser` / `AuthUserProvider` abstraction, unlimited roles, sign-up, e-mail password reset (**optional**), **e-mail verification** and **TOTP two-factor authentication** (**optional**), **events, Micrometer metrics and a health indicator**. Reusable in any Spring Boot 4 / Java 21 project.

- Coordinates: `zrouga.spring:security-starter:2.2.0` (see `CHANGELOG.md` for breaking changes)
- Auto-configured via `AutoConfiguration.imports`: nothing to import, adding the dependency is enough.
- License: MIT.

## 1. Dependency (consumer project)

```xml
<repositories>
    <repository>
        <id>github</id>
        <url>https://maven.pkg.github.com/karimzrouga/zrouga-spring-security</url>
    </repository>
</repositories>

<dependencies>
    <!-- spring-boot-starter-web is OPTIONAL in the starter: declare it here -->
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

GitHub Packages requires authentication even for reads: add to `~/.m2/settings.xml`

```xml
<servers>
    <server>
        <id>github</id>
        <username>YOUR_GITHUB_LOGIN</username>
        <password>YOUR_PAT_READ_PACKAGES</password>
    </server>
</servers>
```

## 2. Configuration

```yaml
zrouga:
  security:
    jwt-secret: <base64, >= 64 decoded bytes>        # required
    jwt-expiration-ms: 1800000                       # default: 30 min
    jwt-refresh-expiration-ms: 86400000              # default: 24 h
    auth-mode: header                                # default: header | cookie (§11)
    cookie-secure: false                             # Secure flag on auth cookies (true over HTTPS)
    cookie-same-site: Lax                            # SameSite of cookies: Lax | Strict | None
    public-paths:                                    # default: /api/auth/**
      - /api/auth/**
    rate-limit-max-attempts: 5                       # default: 5 failures then 429
    rate-limit-window-ms: 900000                     # default: 15 min window
    lockout-enabled: false                           # default: account lockout DISABLED
    lockout-max-attempts: 5                          # default: 5 failures then 423
    lockout-duration-ms: 900000                      # default: 15 min lock
    password-policy-enabled: false                   # default: password policy DISABLED
    password-min-length: 8                           # default: minimum length
    password-require-uppercase: true                 # default: uppercase required
    password-require-lowercase: true                 # default: lowercase required
    password-require-digit: true                     # default: digit required
    password-require-special: true                   # default: special character required
    password-history-count: 3                        # default: last 3 passwords rejected
    revocation-enabled: false                        # default: jti revocation DISABLED (§10)
    concurrent-sessions-enabled: false               # default: single session (a sign-in purges tokens)
    refresh-binding-enabled: false                   # default: IP/UA binding DISABLED (§10)
    trust-forwarded-for: false                       # default: X-Forwarded-For ignored (true behind a proxy)
    cleanup-enabled: false                           # default: expired refresh token purge DISABLED
    cleanup-fixed-delay-ms: 3600000                  # default: purge every 1 h
    reset-enabled: false                             # default: SMTP password reset DISABLED
    reset-base-url: ""                               # required if reset-enabled=true (front URL)
    reset-token-expiration-ms: 900000                # default: token valid 15 min
    reset-email-from: ""                             # default: spring.mail.username
    email-verification-enabled: false                # default: e-mail verification DISABLED (§16)
    email-verification-base-url: ""                  # required if enabled (front URL)
    email-verification-token-ttl-ms: 86400000        # default: token valid 24 h
    email-verification-from: ""                      # default: spring.mail.username
    two-factor-enabled: false                        # default: TOTP 2FA DISABLED (§17)
    two-factor-issuer: zrouga                        # default: "zrouga" (in otpauth://)
    two-factor-challenge-ttl-ms: 300000              # default: challenge valid 5 min
```

The secret must be a **valid standard Base64** (A-Z, a-z, 0-9, +, /, =) decoding to **at least 64 bytes (512 bits)** — an HS512 requirement, checked at startup. Generation: `openssl rand -base64 64`.

## 3. Implement the bridge to your project (mandatory)

Implement `AuthUser` (your users) and `AuthUserProvider` (their access):

```java
@Component
public class MyAuthUserProvider implements AuthUserProvider {

    private final UserRepository repository; // your entity / your table

    @Override
    public Optional<AuthUser> findByEmail(String email) {
        return repository.findByEmail(email).map(this::toAuthUser);
    }

    @Override
    public Optional<AuthUser> findById(Long id) {
        return repository.findById(id).map(this::toAuthUser);
    }

    private AuthUser toAuthUser(User u) {
        return new AuthUser() {
            public Long getId() { return u.getId(); }
            public String getEmail() { return u.getEmail(); }
            public String getPassword() { return u.getPassword(); }        // hash
            public List<String> getRoles() { return List.of(u.getRole().name()); } // unlimited
            public Boolean getStatus() { return u.getActive(); }           // false = disabled account
        };
    }
}
```

Without an `AuthUserProvider` bean, startup fails with an explicit message.

To enable sign-up (`/api/auth/signup`), also declare an `AuthUserCreator` bean — see §5.

## 4. Exposed endpoints

| Method | Path | Body / response |
|---|---|---|
| POST | `/api/auth/signup` | `{email, password}` → `{message}` (**201**) |
| POST | `/api/auth/signin` | `{email, password}` → `{token, type: "Bearer", refreshToken}` (or 2FA challenge, §17) |
| POST | `/api/auth/forgot-password` | `{email}` → `{message}` (**200**, always identical — if `reset-enabled`) |
| POST | `/api/auth/reset-password` | `{token, password}` → `{message}` (**200** — if `reset-enabled`) |
| POST | `/api/auth/refreshtoken` | `{refreshToken}` → `{accessToken, refreshToken, tokenType: "Bearer"}` (**refreshToken rotated**) |
| POST | `/api/auth/signout` | (Bearer) → `{message}` |
| POST | `/api/auth/verify-email` | `{token}` → `{message}` (**if `email-verification-enabled`**, §16) |
| POST | `/api/auth/resend-verification` | `{email}` → `{message}` (**always identical** — anti-enumeration) |
| POST | `/api/auth/2fa/setup` | (Bearer) → `{secret, otpauthUri}` (§17) |
| POST | `/api/auth/2fa/enable` | (Bearer) `{code}` → `{message}` (§17) |
| POST | `/api/auth/2fa/disable` | (Bearer) `{code}` → `{message}` (§17) |
| POST | `/api/auth/2fa/verify` | `{twoFactorToken, code}` → full tokens (§17) |

In `cookie` mode (§11): `/signin` and `/refreshtoken` also set the auth cookies (JSON body
unchanged), `/refreshtoken` accepts an empty body (the `zrouga_refresh` cookie is read
automatically) and `/signout` clears the cookies.

### Errors — unified format

All starter errors (400, 401, 403, 409, 423, 429, 501) look like:

```json
{ "status": 403, "error": "Forbidden", "message": "...", "path": "/api/auth/refreshtoken", "timestamp": "2026-11-22T12:00:00Z" }
```

| Case | Status |
|---|---|
| Missing / invalid JWT, inactive account, wrong password | 401 |
| Unknown, expired or already-rotated refresh token | 403 |
| Refresh token whose IP/UA binding no longer matches (`refresh-binding-enabled`) | 403 |
| E-mail already used at sign-up | 409 |
| Invalid, expired or reused password-reset token | 400 |
| Invalid, expired or reused e-mail verification token | 400 `verification_token_invalid` |
| Too many sign-in attempts (`rate-limit-max-attempts`) | 429 |
| Account locked after N failures (`lockout-max-attempts`) — code `account_locked` | 423 |
| Password rejected by policy (`password-policy-enabled`) — code `weak_password` | 400 |
| Invalid request body (`@Valid` validation) | 400 |
| Sign-up without an `AuthUserCreator` bean | 501 `signup_not_supported` |
| Reset disabled (`reset-enabled=false`) | 501 `reset_not_supported` |
| E-mail verification disabled (`email-verification-enabled=false`) | 501 `verification_not_supported` |
| 2FA disabled (`two-factor-enabled=false`) on `/2fa/*` | 501 `two_factor_not_supported` |
| Invalid TOTP code | 400 `invalid_two_factor_code` |
| Missing or expired 2FA challenge (`/2fa/verify`) | 401 `two_factor_token_invalid` |

Error messages **never** contain the refresh token value.

Everything else in the API is `authenticated()` except `public-paths`.

## 5. Sign-up — `POST /api/auth/signup`

Body: `{"email": "...", "password": "..."}` — password of **8 to 128 characters**, valid e-mail.
`201` response: `{"message": "User registered successfully!"}` then sign in via `/signin`.
With `password-policy-enabled=true`, the password must also satisfy the policy (§13) → `400 weak_password`.

Sign-up is **public** (covered by `public-paths` = `/api/auth/**`). To enable it, declare an
`AuthUserCreator` bean — your project actually creates the user:

```java
@Component
public class MyAuthUserCreator implements AuthUserCreator {

    private final UserRepository repository; // your entity / your table

    @Override
    public void create(String email, String encodedPassword) {
        User u = new User();
        u.setEmail(email);
        u.setPassword(encodedPassword);   // BCrypt hash already produced by the starter
        u.setRole(Role.USER);             // ← roles are DECIDED HERE
        u.setActive(true);
        repository.save(u);
    }
}
```

> **Roles never come from the client**: the sign-up body only contains `email` and `password`.
> `AuthUserCreator` assigns the role (default role, manual validation, …) — otherwise a new
> user could self-elevate to `ADMIN`.

| Case | Status |
|---|---|
| Sign-up succeeded | 201 |
| E-mail already used | 409 |
| No `AuthUserCreator` bean declared | 501 (message: "declare an AuthUserCreator bean…") |
| Invalid body (e-mail, password < 8 chars) | 400 |
| Password rejected by policy (§13) — `weak_password` | 400 |
| Too many failed sign-ups for the same e-mail (rate limit) | 429 |

## 6. Password reset (optional — SMTP)

**Disabled by default** — enable it only if you need it:

```yaml
zrouga:
  security:
    reset-enabled: true                              # enables the feature
    reset-base-url: https://my-front.test/reset      # required (front page)
    reset-token-expiration-ms: 900000                # default: token valid 15 min
    reset-email-from: no-reply@my-project.test       # default: spring.mail.username
spring:
  mail:                                              # SMTP — requires spring-boot-starter-mail
    host: smtp.example.test
    port: 587
    username: user@my-project.test
    password: ***
```

At startup with `reset-enabled=true`, the starter **fails with an explicit message** if
`reset-base-url`, the `AuthUserPasswordUpdater` bean or the `JavaMailSender` (`spring.mail.*`)
is missing. Without `reset-enabled`, no requirements — both endpoints answer 501.

### Mandatory SPI — `AuthUserPasswordUpdater`

```java
@Component
public class MyPasswordUpdater implements AuthUserPasswordUpdater {

    private final UserRepository repository; // your entity / your table

    @Override
    public void updatePassword(String email, String encodedPassword) {
        User u = repository.findByEmail(email).orElseThrow();
        u.setPassword(encodedPassword);   // BCrypt hash already produced by the starter
        repository.save(u);
    }
}
```

### Flow

| Step | Call | Response |
|---|---|---|
| 1. Request | `POST /api/auth/forgot-password` `{email}` | **200** always identical (anti-enumeration) — the e-mail is only sent if the account exists |
| 2. Link | SMTP e-mail: `{reset-base-url}?token=…` | random 256-bit token, valid 15 min, **single use** |
| 3. New password | `POST /api/auth/reset-password` `{token, password}` | **200** — hash stored + **all refresh tokens of the account revoked** |

- **Rate limit**: 5 requests / 15 min per e-mail (known account or not — no enumeration via 429).
- Invalid, expired or reused token → **400** `Invalid or expired reset token.` (same message everywhere).
- **Password policy** (§13, if `password-policy-enabled=true`): the new password is validated
  **before** the token is consumed — a rejection (`400 weak_password`) leaves the token usable.
- **SMTP by default** (`SmtpPasswordResetEmailSender`); customize with your own
  `PasswordResetEmailSender` bean (SendGrid, business API, dev console…) — `spring.mail.*` is
  then not required.
- In-memory storage by default; declare `PasswordResetTokenStore` for distributed persistence
  (Redis, SQL table).

## 7. Role-based authorization — non-public APIs

Default model: `public-paths` (default `/api/auth/**`) → `permitAll()`; **everything else** →
`authenticated()` (valid JWT + active account). To additionally require a role on a non-public
route, two approaches:

### Declare a PUBLIC or PRIVATE endpoint

**Public** (no token) = declared in `zrouga.security.public-paths` — **private** = everything else, automatically.

```yaml
zrouga:
  security:
    public-paths:                # ← only these paths are PUBLIC
      - /api/auth/**             # default: signup, signin, refreshtoken, signout, 2fa, verify-email
      - /api/public/**           # ex: open resources
      - /health                  # ex: exact path
```

| Declaration | Private endpoint (default) | Public endpoint | Private + role |
|---|---|---|---|
| **Where** | nothing to do — outside `public-paths` | `public-paths` (YAML) | `@PreAuthorize` or `SecurityFilterChain` |
| **Requirement** | valid JWT + active account → else **401** | none | missing role → **403** |
| **Example** | `GET /api/hello` | `POST /api/auth/signup` | `GET /api/admin/stats` |

- Spring patterns: `*` = one segment, `**` = several segments, no wildcard = exact path.
- The YAML list **replaces** the default: repeat `/api/auth/**` if you add other paths.
- Careful: the wider the list (`/**`), the more endpoints escape authentication —
  declare strictly what must be.

### a) By annotation (recommended — `@EnableMethodSecurity` already active)

```java
@RestController
@RequestMapping("/api/admin")
public class AdminResource {

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/stats")
    public Stats stats() { ... }                 // 403 if ADMIN role missing

    @PreAuthorize("hasAnyRole('ADMIN', 'AQP')")
    @GetMapping("/reports")
    public List<Report> reports() { ... }        // 403 if neither ADMIN nor AQP
}
```

On a whole class: put `@PreAuthorize("hasRole('ADMIN')")` above `public class …`.

### b) By route (declare your own `SecurityFilterChain`)

Your bean replaces the starter's (`@ConditionalOnMissingBean`):

```java
@Bean
SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.csrf(AbstractHttpConfigurer::disable)
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/auth/**").permitAll()            // public
            .requestMatchers("/api/admin/**").hasRole("ADMIN")      // role required
            .requestMatchers("/api/control/**").hasAnyRole("ADMIN", "AQP")
            .anyRequest().authenticated())                           // rest: valid token
        .exceptionHandling(e -> e.authenticationEntryPoint(unauthorizedHandler))
        .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    return http.build();
}
```

### Best practices

- **`hasRole('X')` without prefix**: JWT claims carry `ADMIN` (no `ROLE_`) and the prefix is
  added automatically when authorities are built — write `hasRole("ADMIN")`, **never**
  `hasRole("ROLE_ADMIN")` (otherwise permanent 403).
- No token → **401**; valid token but missing role → **403**.
- The rule applies on **every server-side request**: the front-end only handles display.
- Roles come from `AuthUser.getRoles()`: unlimited, raw values (`"ADMIN"`, `"AQP"`, …).
- `requestMatchers` order matters: specific rules before `anyRequest().authenticated()`.

## 8. JWT claims (HS512)

`sub` = email, `id`, `email`, `roles` (unlimited list, raw values), `status` (Boolean), `exp`,
`jti` (unique identifier — used for revocation, §10).
Signature: `zrouga.security.jwt-secret`.

On the Spring Security side, authorities are built with the standard `ROLE_` prefix:
use `@PreAuthorize("hasRole('ADMIN')")` (not `hasAuthority('ADMIN')`) — details in §7.

## 9. Disabled accounts (status)

- `AuthUser.getStatus()` returns `false` → **sign-in refused** (401);
- an existing JWT of a disabled account is **rejected on every request** (the `status` claim is checked);
- `null` = no information → active account.

## 10. Refresh token

- **Hashed in DB**: the database only stores the **SHA-256 hash** of the token (`TokenHashing`) — a database leak yields no usable token.
- **Rotation**: every `/refreshtoken` revokes the old token and issues a new one (atomic CAS operation, concurrency-safe).
- **Reuse = detected theft**: presenting an already-rotated token revokes the user's **entire family** and answers 403 (`refresh_token_rejected`).
- **Sign-in**: by default (`concurrent-sessions-enabled=false`), a new `signin` revokes all
  previous refresh tokens of the user (single-session policy); `true` allows concurrent sessions.
- **Access token revocation** (`revocation-enabled=true`): the JWT's `jti` is recorded at
  sign-out (`/signout`) and rejected on every request until the token expires —
  a 10,000-token in-memory ceiling (overridable store: `AccessTokenRevocationStore`).
- **IP/UA binding** (`refresh-binding-enabled=true`): each refresh token memorizes the IP and
  `User-Agent` at issuance; a rotation from another IP/UA answers 403 (tokens issued without
  binding stay valid if binding is later disabled).
- **With JPA** (`spring-boot-starter-data-jpa` present): `refreshtoken` table created
  automatically (`user_id`, `token` (unique hash), `expiry_date`, `revoked`, `ip`, `user_agent`,
  index), store `JpaRefreshTokenStore`.
- **Without JPA**: in-memory store (`InMemoryRefreshTokenStore`).
- **Expired purge**: optional — `zrouga.security.cleanup-enabled=true` activates a periodic purge
  (`cleanup-fixed-delay-ms`), also for reset tokens (§6).
- Customizable: declare your own `RefreshTokenStore` bean — auto-configs back off.

## 11. Authentication modes

Two modes, switchable via `zrouga.security.auth-mode` — an unknown value **fails startup**
(no silent fallback):

| Mode | Access token | Refresh token | Nature |
|---|---|---|---|
| `header` (default) | `Authorization: Bearer <JWT>` header | JSON body of `POST /refreshtoken` | **Stateless JWTs** |
| `cookie` | `zrouga_access` cookie (`HttpOnly`, `Path=/`) | `zrouga_refresh` cookie (`HttpOnly`, `Path=/api/auth`) | **Stateful Session Cookies** |

### `header` mode (default)

Historical behavior: the front-end stores both tokens and sends the refresh token
in the `/refreshtoken` body.

### `cookie` mode

- `/signin` and `/refreshtoken` **set** both cookies (re-issued on every rotation,
  therefore invisible to the browser); the JSON body is unchanged — the tokens are
  also there, curl tests remain possible.
- The filter reads the `Authorization` header **then** the cookie; `/refreshtoken` reads
  the body **then** the cookie: both transports coexist on the same application.
- `/signout` and a **successful** `/reset-password` clear both cookies (`Max-Age=0`);
  a failure leaves the session intact.
- Flags: `cookie-secure` (default `false` for HTTP dev → `true` in HTTPS production)
  and `cookie-same-site` (default `Lax`; `None` requires `cookie-secure: true` when
  the front-end is on another domain).
- **SPA front-end**: `withCredentials: true` + CORS `allowCredentials(true)` with
  **explicit origins** (never `*`).
- **CSRF**: CSRF stays disabled in the chain — `SameSite=Lax` cookies (default) are
  not sent cross-site; prefer `Strict` if front and API share a domain.
- The Spring session stays `STATELESS` (no `HttpSession`): the cookies only carry tokens.

```yaml
zrouga:
  security:
    auth-mode: cookie            # default: header
    cookie-secure: false         # true in production (HTTPS)
    cookie-same-site: Lax        # Lax | Strict | None
```

See the demos: `examples/demo-jwt` (header) and `examples/demo-cookie` (cookie).

## 12. Rate limiting (anti-bruteforce)

5 failed attempts per e-mail then a 15-minute block (429), by default — tunable via
`rate-limit-max-attempts` / `rate-limit-window-ms`. A successful sign-in resets the counter.

- **Keys**: `signin|signup|forgot|verification:email:<email>` and `…:ip:<ip>` — the IP quota is **×10** the e-mail quota.
- **Atomic check**: the attempt is **reserved** before authentication (a failure consumes the quota); `429` carries code `rate_limit_exceeded`.
- **Behind a proxy**: `zrouga.security.trust-forwarded-for: true` reads `X-Forwarded-For` (default `false`: real IP).
- Customizable: declare your own `LoginRateLimiter` bean (database, Redis, …).

### Account lockout (optional)

`zrouga.security.lockout-enabled: true` adds a **per-account** lock, on top of rate limiting:

- after `lockout-max-attempts` consecutive failures (default 5), the account answers **423**
  `account_locked` for `lockout-duration-ms` (default 15 min) — **even with the correct password**;
- a successful sign-in or lock expiry reset the counter (after expiry, it starts from zero);
- an **unknown** account locks the same way: no different observable = no e-mail enumeration;
- attempts on a locked account still hit the rate limit (the lock does not protect against floods);
- complementary to rate limiting: rate limit protects **per e-mail/IP** (sliding window),
  lockout **per account** (fixed duration);
- in-memory by default (lost on restart, 10,000 tracked accounts ceiling) — declare your own
  `AccountLockoutService` bean to persist (Redis, database, admin unlock via `reset(email)`).

## 13. Password policy (optional)

`zrouga.security.password-policy-enabled: true` validates the password on `/signup` and
`/reset-password` → **400** `weak_password`, with the list of **all** missing rules in the message.

- **Rules**: `password-min-length` (default 8), `password-require-uppercase`, `password-require-lowercase`,
  `password-require-digit`, `password-require-special` (all default `true`; special = non-alphanumeric
  non-space character).
- **Anti-reuse**: `password-history-count` (default 3, `0` = only the current password is checked) —
  on reset, the **current** and **previous** passwords are rejected (`400 weak_password`).
- **Token preserved**: on `/reset-password`, the policy is validated **before** the token is
  consumed — a rejection leaves the token usable for a new attempt.
- The DTO `@Size` validation (8 to 128 characters) stays active even without the policy.
- In-memory history by default (lost on restart; the current password's hash is always checked) —
  declare your own `PasswordHistoryStore` bean to persist it.
- Customizable: declare your own `PasswordPolicy` bean (password dictionary, NIST SP 800-63B, …).

## 14. Customization

All the following beans are overridable — declare yours and the starter's is replaced:

| Bean | Starter default |
|---|---|
| `SecurityFilterChain` | stateless JWT chain |
| `PasswordEncoder` | `BCryptPasswordEncoder` |
| `AuthenticationManager` | via `AuthenticationConfiguration` |
| `AuthenticationProvider` | `DaoAuthenticationProvider` |
| `UserDetailsService` | reads through `AuthUserProvider` |
| `JwtUtils` | HS512 + secret `zrouga.security.jwt-secret` |
| `AuthTokenFilter` | Bearer filter (and `zrouga_access` cookie in `cookie` mode) |
| `RefreshTokenService` | tokens with configurable expiry |
| `RefreshTokenStore` | JPA if available, else in-memory |
| `AccessTokenRevocationStore` | in-memory (`jti` revocation, 10,000 ceiling) |
| `LoginRateLimiter` | in-memory (per-e-mail window) |
| `AccountLockoutService` | in-memory (account lockout) |
| `PasswordPolicy` | length + complexity (`password-*`) |
| `PasswordHistoryStore` | in-memory (anti-reuse) |
| `PasswordResetTokenStore` | in-memory (reset tokens) |
| `PasswordResetEmailSender` | SMTP (`spring.mail.*`), only if `reset-enabled=true` |
| `AuthUserPasswordUpdater` | host-project SPI (required if `reset-enabled=true`) |
| `EmailVerificationTokenStore` | in-memory (verification tokens, §16) |
| `EmailVerificationEmailSender` | async SMTP (`spring.mail.*`), only if `email-verification-enabled=true` |
| `AuthUserEmailVerifier` | host-project SPI (required if `email-verification-enabled=true`) |
| `TwoFactorSecretStore` | in-memory (TOTP secrets, §17) |
| `AuthService`, `AuthResource`, `AuthEntryPointJwt`, `TokenControllerAdvice`, `PasswordResetService`, `EmailVerificationService` | default implementations |

- Full exclusion: `spring.autoconfigure.exclude=zrouga.spring.security.autoconfigure.ZrougaSecurityAutoConfiguration`
- `AuthUserCreator`: host-project SPI (see §5) — without it, `/signup` answers 501.
- CORS: defined on the host-project side (no hardcoded origin in the starter).
- `@CrossOrigin` removed: configure CORS via your `CorsConfigurationSource` / `WebMvcConfigurer`.
- **GraalVM native image**: hints provided (`ZrougaRuntimeHints` + `META-INF/spring/aot.factories`) for reflected DTOs.
- **Errors**: `AuthException` + subclasses carry a machine `code()`; `TokenControllerAdvice`
  only handles starter exceptions (declare your own for your controllers).
- **Events**: every event in §18 is published via `ApplicationEventPublisher` —
  listen to them with `@EventListener` in your project.

## 15. Build / publication (maintainer)

```powershell
.\mvnw.cmd verify          # tests + jacoco + japicmp + jar + sources + javadoc
$env:GITHUB_TOKEN = gh auth token   # scope write:packages
.\mvnw.cmd deploy          # → GitHub Packages
```

- **GitHub Actions CI** (`.github/workflows/ci.yml`): builds the previous release then
  runs `mvnw verify` (tests + JaCoCo + **japicmp**) on every push/PR; publishes on
  tag `v*` + **creates the GitHub release with automatic notes**.
- **CodeQL** (`.github/workflows/codeql.yml`): security analysis on every push/PR + weekly.
- **Dependabot** (`.github/dependabot.yml`): weekly Maven (root + demos) and GitHub Actions updates.
- **Release**: full process in [`RELEASING.md`](RELEASING.md) (version bump,
  `japicmp.oldVersion`, CHANGELOG, tag `v2.2.0` → CI publishes and generates the notes).
- **Application examples**: `examples/demo-jwt/` (stateless JWT in header) and
  `examples/demo-cookie/` (stateful session cookies) — the starter must be `mvnw install`ed
  locally before building them.
- **Coverage**: JaCoCo report in `target/site/jacoco/` (locked thresholds: ≥ 80 % instructions, ≥ 55 % branches).
- **Binary compatibility**: japicmp report in `target/japicmp/japicmp.md` — any binary
  break fails the build (`@Deprecated` shims or targeted exclusions).
- **IDE metadata**: auto-completion and descriptions of `zrouga.security.*` properties (configuration-processor).

Source repository: https://github.com/karimzrouga/zrouga-spring-security

## 16. E-mail verification (optional)

**Disabled by default.** On first activation: declare the `AuthUserEmailVerifier` SPI
(startup fails with an explicit message if missing), `email-verification-base-url`
and a `JavaMailSender` (or your own `EmailVerificationEmailSender`).

```yaml
zrouga:
  security:
    email-verification-enabled: true
    email-verification-base-url: https://my-front.test/verify   # front page
    email-verification-token-ttl-ms: 86400000                    # 24 h
    email-verification-from: no-reply@my-project.test            # default: spring.mail.username
```

```java
@Component
public class MyEmailVerifier implements AuthUserEmailVerifier {

    private final UserRepository repository;

    @Override
    public void verifyEmail(String email) {
        repository.findByEmail(email).ifPresent(u -> u.setEmailVerified(true));
    }
}
```

### Flow

| Step | Call | Response |
|---|---|---|
| 1. Sign-up | `POST /signup` → `SignUpEvent` | 256-bit token issued (24 h TTL) + e-mail sent **asynchronously**: `{email-verification-base-url}?token=…` |
| 2. Verification | `POST /verify-email` `{token}` | **200** — token consumed (single use) + `AuthUserEmailVerifier.verifyEmail(email)` called |
| 3. Resend | `POST /resend-verification` `{email}` | **200** always identical (anti-enumeration) — new token issued if the account exists |

- **Rate limit**: per e-mail, per IP, and per IP on verification tokens (keys `verification:*`).
- Invalid, expired or reused token → **400** `verification_token_invalid` (same message everywhere).
- Without `email-verification-enabled`, the endpoints answer **501** `verification_not_supported`.
- In-memory storage by default; declare `EmailVerificationTokenStore` for distributed persistence.
- The default SMTP sender is **asynchronous** (sign-up does not wait on the network).

## 17. Two-factor authentication — TOTP (optional)

**Disabled by default.** Works with any TOTP authenticator (Google Authenticator, Authy,
1Password…): RFC 6238, SHA-1, 6 digits, 30 s step, ±1 window.

```yaml
zrouga:
  security:
    two-factor-enabled: true
    two-factor-issuer: my-project           # default: "zrouga"
    two-factor-challenge-ttl-ms: 300000     # default: challenge valid 5 min
```

### Flow

| Step | Call | Response |
|---|---|---|
| 1. Enable | `POST /2fa/setup` (Bearer) | **200** `{secret, otpauthUri}` — enter the secret manually or encode `otpauthUri` as a QR on the front |
| 2. Confirm | `POST /2fa/enable` (Bearer) `{code}` | **200** — a valid TOTP code required; 2FA active for the account |
| 3. Sign-in | `POST /signin` (2FA active) | **200** `{twoFactorRequired: true, twoFactorToken}` — **no tokens issued** before verification |
| 4. Verify | `POST /2fa/verify` `{twoFactorToken, code}` | **200** full tokens (+ cookies in `cookie` mode) |
| 5. Disable | `POST /2fa/disable` (Bearer) `{code}` | **200** — proof by the current code required |

- The `twoFactorToken` challenge is a scoped JWT (claim `2fa`), valid for
  `two-factor-challenge-ttl-ms` (5 min by default).
- Secrets stored via `TwoFactorSecretStore` (in-memory by default — declare your own to
  persist: SQL table, Redis).
- Without `two-factor-enabled`, the `/2fa/*` endpoints answer **501** `two_factor_not_supported`.
- Expired or wrong code → **400** `invalid_two_factor_code`; missing/expired challenge → **401** `two_factor_token_invalid`.
- Both transports (header / cookie) work with the challenge.

## 18. Observability — events, metrics, health

### Spring events

Published via `ApplicationEventPublisher` — listen with `@EventListener`:

| Event | Published when |
|---|---|
| `SignInEvent` | successful sign-in |
| `SignInFailedEvent` | failed sign-in (password, rate limit, lockout, inactive account) |
| `SignUpEvent` | sign-up created |
| `SignOutEvent` | sign-out (`/signout`) |
| `TokenRefreshedEvent` | successful refresh token rotation |
| `LockoutEvent` | account locked (`lockout-enabled`) |
| `PasswordResetEvent` | password reset |
| `EmailVerifiedEvent` | e-mail verified (§16) |

### Micrometer metrics

Requires `spring-boot-starter-actuator` (optional in the starter) on the consumer
project's classpath. Counters exposed through any `MeterRegistry`:

| Counter | Tags |
|---|---|
| `zrouga.security.signin` | `outcome=success\|failure` |
| `zrouga.security.signup` | — |
| `zrouga.security.signout` | — |
| `zrouga.security.token.refresh` | — |
| `zrouga.security.account.lockout` | — |
| `zrouga.security.password.reset` | — |
| `zrouga.security.email.verified` | — |

### Health indicator

With the actuator exposed (`/actuator/health`), the **`zrougaSecurity`** component
summarizes the **configuration** (always `UP` — it depends on no external service):

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

## 19. FAQ / Troubleshooting

**`401` on every request even with a valid token**
→ Invalid secret (Base64 ≥ 64 bytes), missing `Authorization: Bearer <JWT>` header, or
`AuthUser.getStatus()` = `false` (disabled account, §9). Also check the clock (`exp`).

**`403 refresh_token_rejected` after a refresh**
→ An already-rotated token was reused: the **entire family** is revoked (§10). The front-end
must store the `refreshToken` returned by each `/refreshtoken`. With
`refresh-binding-enabled=true`, a change of IP or `User-Agent` also produces this 403.

**Cookies are not set (`cookie` mode)**
→ `cookie-secure: true` requires HTTPS; `cookie-same-site: None` requires `cookie-secure: true`;
front on another domain → `SameSite=None` + CORS `allowCredentials(true)` with explicit
origins. In curl, use `-c`/`-b` for the cookie jar.

**`501 verification_not_supported` / `501 two_factor_not_supported`**
→ Feature disabled: enable `email-verification-enabled` (§16) or `two-factor-enabled`
(§17) — and check the prerequisites (SPI, base URL, SMTP).

**`501 signup_not_supported` or a "declare an AuthUserCreator bean" message**
→ Declare the host-project SPI (§3/§5): `AuthUserCreator`, `AuthUserPasswordUpdater`
(reset), `AuthUserEmailVerifier` (e-mail verification).

**Startup failure: "no … bean declared" or invalid secret**
→ Explicit messages at startup: a SPI required by an enabled option is missing, or
`jwt-secret` is not valid Base64 ≥ 64 bytes (§2).

**`429 rate_limit_exceeded`**
→ Window of 5 attempts / 15 min (§12). Behind a proxy: `trust-forwarded-for: true`.
Need a higher limit: declare your own `LoginRateLimiter`.

**`423 account_locked`**
→ `lockout-enabled`: 5 failures → 15 min lock (§12). Unlock: wait, or a custom
`AccountLockoutService` bean with `reset(email)`.

**No `zrouga.security.*` metrics**
→ Add `spring-boot-starter-actuator` to the consumer project and expose an endpoint
(`management.endpoints.web.exposure.include`); Spring Boot's Micrometer registry does the rest.

**`/actuator/health` does not show `zrougaSecurity`**
→ Same cause: actuator missing from the classpath or the health endpoint not exposed (§18).

**The `JpaRefreshTokenStorePostgresTest` test is "skipped"**
→ Normal without Docker: the Testcontainers test skips itself (`disabledWithoutDocker`)
and runs in CI. Install Docker to run it locally.

**japicmp does not run ("ignore missing old version")**
→ The previous version (`japicmp.oldVersion`) is not in your `~/.m2`: CI builds it from
the `vX.Y.Z` tag; locally, install it once from the tag (see `RELEASING.md`).
