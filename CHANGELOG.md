# Changelog

Toutes les versions notables de `zrouga.spring:security-starter`.
Les versions antérieures à 2.0.0 sont décrites dans les releases GitHub.

## [2.0.0] - 2026-11-23

Version de rupture : renforcement de la sécurité des tokens, contrat d'erreur
machin-readable, messages d'API en anglais. Les versions antérieures ne sont pas
compatibles avec les données (tokens) ni les implémentations SPI de cette version.

### Breaking

- **Refresh tokens hachés (SHA-256)** : les jetons émis par les versions
  précédentes (stockés en clair) deviennent invalides — reconnexion requise après
  l'upgrade.
- **Réutilisation d'un refresh token = vol détecté** : la famille entière de
  l'utilisateur est révoquée (`deleteByUserId`) et la requête répond
  `403 refresh_token_rejected`. Auparavant la rotation supprimait le jeton
  consommé sans révocation de famille.
- **`RefreshTokenStore`** : `deleteByToken(String)` remplacé par
  `revoke(String) → boolean` (CAS atomique : `false` si le jeton était déjà
  révoqué ou absent) ; `deleteExpired(Instant)` ajouté (défaut : no-op).
- **`StoredRefreshToken`** : nouveau composant `revoked` (record à 4 composants :
  token, userId, expiryDate, revoked).
- **`RefreshTokenService`** : `createRefreshToken(AuthUser)` →
  `createRefreshToken(long userId)` ; `revoke(...)` retourne `boolean`.
- **`LoginRateLimiter`** : interface redéfinie — `check(String)`,
  `checkIp(String)`, `reset(String)` ; `recordFailure` supprimé. `check`
  **réserve** atomiquement l'essai : une tentative échouée consomme le quota.
- **Rate-limiting élargi** : clés `signin|signup|forgot:email:` et
  `signin|signup|forgot:ip:` (quota ×10 par IP) ; dépassement →
  `429 rate_limit_exceeded`.
- **`TokenControllerAdvice` limité au starter** (`basePackages`) : les exceptions
  des contrôleurs de l'application ne sont plus interceptées par le format
  d'erreur du starter — déclarez votre propre `@RestControllerAdvice`.
- **Messages d'API en anglais** (l'anglais reste la langue des contrats) ; les
  exceptions du starter héritent de `AuthException` avec un `code()` lisible par
  machine : `rate_limit_exceeded`, `refresh_token_rejected`,
  `email_already_used`, `signup_not_supported`, `reset_not_supported`,
  `reset_token_invalid`.
- **DTOs en `record`** : `JwtResponse`, `MessageResponse`, `TokenRefreshResponse`,
  `ApiError` — JSON inchangé côté champs existants, mais constructeurs et
  fabrique `ApiError.of(...)` changés ; `ApiError` gagne le champ `code`.
- **`spring-boot-starter-web` est optionnel** : l'application doit déclarer sa
  propre dépendance `spring-boot-starter-web`.
- **Validation des e-mails** : `@Email` + `@Size(max = 254)` sur
  signin/signup/forgot → `400` là où l'ancienne version acceptait n'importe
  quelle chaîne.
- **`AuthService`** : `authenticateUser(...)` et `signup(...)` prennent en plus
  l'IP client (appel direct concerné ; l'API HTTP est inchangée).

### Added

- **Inscription** `POST /api/auth/signup` via `AuthUserCreator` (les rôles ne
  viennent jamais de la requête ; e-mail déjà utilisé → `409` + hash BCrypt
  factice pour ne pas révéler le compte).
- **Réinitialisation SMTP optionnelle** : `POST /api/auth/forgot-password` et
  `POST /api/auth/reset-password` (`reset-enabled`, `reset-base-url`), e-mail
  envoyé en asynchrone (TaskExecutor + pool daemon de repli), jeton de reset
  `claim-first` (consommation atomique avant mise à jour du mot de passe).
- **Hachage SHA-256 des refresh tokens** (`TokenHashing`) : la base JPA stocke
  uniquement le hash, avec index `(user_id, expiry_date)` et colonne `revoked`.
- **Rate-limit par IP** + propriété `zrouga.security.trust-forwarded-for`
  (défaut `false`) pour faire confiance à `X-Forwarded-For` derrière un proxy.
- **Statut de compte** : `status = false` → connexion refusée et jetons
  existants rejetés (claim `status` du JWT).
- **`ApiError.code`** : code machine stable à brancher côté client (jamais le
  message, qui peut changer sans préavis).
- **Hints natifs GraalVM** : `ZrougaRuntimeHints` + `META-INF/spring/aot.factories`
  (DTO réfléchis pour les images natives).
- **Purge** : `RefreshTokenCleanup` purge aussi les jetons de réinitialisation ;
  le store en mémoire purge opportunément au-delà de 10 000 entrées.
- **Exemple d'application** : `examples/demo/` (comptes mémoire, endpoint
  protégé `/api/me`, flux signin/refresh/signup documenté).
- **Couverture verrouillée** : règle `jacoco:check` au build (≥ 80 %
  d'instructions, ≥ 55 % de branches).

### Changed

- CORS : `.cors(withDefaults())` uniquement si un `CorsConfigurationSource` est
  déclaré (comportement identique sans bean).
- Logs des tokens et des rejets 401 en `debug` (les `warn` étaient trop
  bruyants en production).
