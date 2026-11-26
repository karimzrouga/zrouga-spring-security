package zrouga.spring.security;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Propriétés de configuration du starter, préfixe {@code zrouga.security}.
 */
@ConfigurationProperties(prefix = "zrouga.security")
public class ZrougaSecurityProperties {

    /** Secret de signature HS512 (Base64 standard, >= 64 octets décodés) — obligatoire, sans valeur par défaut. */
    private String jwtSecret;

    /** Durée de vie de l'access token en millisecondes (défaut : 30 minutes). */
    private long jwtExpirationMs = 1_800_000L;

    /** Durée de vie du refresh token en millisecondes (défaut : 24 heures). */
    private long jwtRefreshExpirationMs = 86_400_000L;

    /**
     * Déclaration des endpoints <b>PUBLICS</b> (accessibles sans jeton) — <b>tous les
     * autres endpoints sont PRIVÉS</b> par défaut : jeton Bearer valide + compte actif
     * exigés, sinon 401.
     *
     * <p>À la construction de la chaîne de filtres, ces chemins reçoivent
     * {@code permitAll()} puis {@code anyRequest().authenticated()}.</p>
     *
     * <p><b>Déclarer un endpoint PUBLIC</b> — ajoutez son motif dans la configuration :</p>
     * <pre>{@code
     * zrouga:
     *   security:
     *     public-paths:
     *       - /api/auth/**      # défaut : signup, signin, refreshtoken, signout
     *       - /api/public/**    # ex : ressources ouvertes
     *       - /health           # ex : chemin exact
     * }</pre>
     * <p>Motifs Spring : {@code *} = un segment ({@code /a/*} ≠ {@code /a/b/c}),
     * {@code **} = zéro ou plusieurs segments, chemin sans joker = correspondance exacte.
     * La liste YAML <b>remplace</b> la valeur par défaut : répétez {@code /api/auth/**}
     * si vous l'ajoutez à côté d'autres chemins.</p>
     *
     * <p><b>Déclarer un endpoint PRIVÉ</b> : rien à faire — tout ce qui n'est pas listé ici
     * est privé automatiquement. Pour exiger <b>en plus</b> un rôle :</p>
     * <ul>
     * <li>annotation sur le contrôleur : {@code @PreAuthorize("hasRole('ADMIN')")}
     *     ({@code @EnableMethodSecurity} est déjà actif) ;</li>
     * <li>ou règles par route : déclarez votre propre bean {@code SecurityFilterChain}
     *     (il remplace celui du starter).</li>
     * </ul>
     * <p>Voir aussi la Javadoc de
     * {@code ZrougaSecurityAutoConfiguration#filterChain} et la §6 du README.</p>
     */
    private List<String> publicPaths = List.of("/api/auth/**");

    /** Nombre maximal de tentatives de connexion échouées avant blocage (défaut : 5). */
    private int rateLimitMaxAttempts = 5;

    /** Fenêtre de comptage des tentatives en millisecondes (défaut : 15 minutes). */
    private long rateLimitWindowMs = 900_000L;

    /**
     * Fait confiance à l'en-tête {@code X-Forwarded-For} pour extraire l'IP réelle du
     * client (derrière un reverse proxy) — <b>défaut : {@code false}</b>.
     *
     * <p>À activer <b>uniquement</b> si un proxy de confiance définit cet en-tête :
     * sinon un client pourrait falsifier sa clé de limitation IP.</p>
     */
    private boolean trustForwardedFor = false;

    /** Active la purge périodique des refresh tokens expirés (défaut : désactivé). */
    private boolean cleanupEnabled = false;

    /** Intervalle de la purge des refresh tokens expirés en millisecondes (défaut : 1 heure). */
    private long cleanupFixedDelayMs = 3_600_000L;

    /**
     * Active la réinitialisation du mot de passe par e-mail SMTP — fonctionnalité
     * <b>optionnelle, désactivée par défaut</b> (défaut : {@code false}).
     *
     * <p>Quand {@code true} au démarrage, le starter vérifie que {@code reset-base-url}
     * est renseigné, qu'un bean {@code AuthUserPasswordUpdater} existe, et qu'un
     * {@code JavaMailSender} est disponible (ajoutez {@code spring-boot-starter-mail}
     * et {@code spring.mail.*}) — sinon le démarrage échoue avec un message explicite.</p>
     */
    private boolean resetEnabled = false;

    /** Durée de validité du jeton de réinitialisation en millisecondes (défaut : 15 minutes). */
    private long resetTokenExpirationMs = 900_000L;

    /**
     * URL de la page de réinitialisation du mot de passe côté front — obligatoire si
     * {@code reset-enabled=true}. Le paramètre {@code ?token=} (ou {@code &token=})
     * y est ajouté pour former le lien reçu par e-mail.
     */
    private String resetBaseUrl = "";

    /**
     * Adresse expéditrice des e-mails de réinitialisation — si vide, utilise
     * {@code spring.mail.username} (doit rester vide uniquement si SMTP fournit l'expéditeur).
     */
    private String resetEmailFrom = "";

    /**
     * Active le <b>verrouillage de compte</b> après N connexions échouées —
     * fonctionnalité <b>optionnelle, désactivée par défaut</b> (défaut : {@code false}).
     *
     * <p>Quand {@code true} : après {@code lockout-max-attempts} échecs consécutifs,
     * le compte répond {@code 423 account_locked} pendant {@code lockout-duration-ms},
     * même avec le bon mot de passe. Une connexion réussie ou la fin du verrou remettent
     * le compteur à zéro. Complémentaire du rate-limit : le rate-limit protège par
     * e-mail/IP, le verrouillage par compte.</p>
     */
    private boolean lockoutEnabled = false;

    /** Connexions échouées avant verrouillage du compte (défaut : 5). */
    private int lockoutMaxAttempts = 5;

    /** Durée du verrouillage de compte en millisecondes (défaut : 15 minutes). */
    private long lockoutDurationMs = 900_000L;

    /**
     * Active la <b>politique de mot de passe</b> (longueur + complexité + anti-réutilisation)
     * sur {@code /signup} et {@code /reset-password} — fonctionnalité <b>optionnelle,
     * désactivée par défaut</b> (défaut : {@code false}).
     *
     * <p>La validation {@code @Size} du DTO (8 à 128 caractères) reste active en permanence ;
     * la politique ajoute les règles de complexité ci-dessous et l'historique
     * {@code password-history-count} à la réinitialisation.</p>
     */
    private boolean passwordPolicyEnabled = false;

    /** Longueur minimale du mot de passe quand la politique est active (défaut : 8). */
    private int passwordMinLength = 8;

    /** Exige au moins une majuscule (défaut : {@code true}). */
    private boolean passwordRequireUppercase = true;

    /** Exige au moins une minuscule (défaut : {@code true}). */
    private boolean passwordRequireLowercase = true;

    /** Exige au moins un chiffre (défaut : {@code true}). */
    private boolean passwordRequireDigit = true;

    /** Exige au moins un caractère spécial, non alphanumérique et non espace (défaut : {@code true}). */
    private boolean passwordRequireSpecial = true;

    /**
     * Nombre de mots de passe précédents interdits à la réinitialisation (défaut : 3,
     * {@code 0} = seul le mot de passe courant est vérifié). S'applique uniquement si
     * {@code password-policy-enabled=true}. L'historique vit en mémoire par défaut —
     * déclarez votre propre bean {@code PasswordHistoryStore} pour le persister.
     */
    private int passwordHistoryCount = 3;

    /**
     * Mode d'authentification — deux options (défaut : {@code header}) :
     *
     * <ul>
     * <li><b>{@code header}</b> — <i>Stateless JWTs</i> : access token transmis via
     *     {@code Authorization: Bearer <JWT>}, refresh token dans le corps JSON de
     *     {@code /refreshtoken} (comportement historique) ;</li>
     * <li><b>{@code cookie}</b> — <i>Stateful Session Cookies</i> : access token en
     *     cookie {@code zrouga_access} ({@code HttpOnly}, {@code Path=/}) et refresh
     *     token en cookie {@code zrouga_refresh} ({@code HttpOnly},
     *     {@code Path=/api/auth}), lus automatiquement par le filtre et les endpoints
     *     d'auth — le corps JSON reste identique (les deux coexistent).</li>
     * </ul>
     *
     * <p>En mode {@code cookie}, pensez côté front à {@code withCredentials: true} et à
     * un CORS {@code allowCredentials(true)} avec origines explicites ; les flags des
     * cookies sont réglés par {@code cookie-secure} et {@code cookie-same-site}.</p>
     */
    private String authMode = "header";

    /**
     * Ajoute le drapeau {@code Secure} aux cookies d'auth (HTTPS uniquement) —
     * défaut {@code false} pour le développement en HTTP ; <b>{@code true} en
     * production</b>.
     */
    private boolean cookieSecure = false;

    /**
     * Active la <b>vérification de l'e-mail à l'inscription</b> — fonctionnalité
     * <b>optionnelle, désactivée par défaut</b> (défaut : {@code false}).
     *
     * <p>Quand {@code true} : après {@code /signup}, un e-mail contenant un jeton
     * usage unique est envoyé ; {@code POST /api/auth/verify-email} consomme le
     * jeton et appelle {@link AuthUserEmailVerifier#verifyEmail(String)} (bean
     * requis). {@code POST /api/auth/resend-verification} renvoie un jeton neuf.
     * L'application décide elle-même de bloquer l'accès tant que l'e-mail n'est
     * pas vérifié (le stockage de l'état reste côté app).</p>
     */
    private boolean emailVerificationEnabled = false;

    /**
     * URL de la page de vérification côté front — obligatoire si
     * {@code email-verification-enabled=true}. Le jeton est ajouté en query
     * param {@code ?token=…}.
     */
    private String emailVerificationBaseUrl;

    /** Durée de vie du jeton de vérification en millisecondes (défaut : 24 heures). */
    private long emailVerificationTokenTtlMs = 86_400_000L;

    /**
     * Adresse expéditrice des e-mails de vérification — si absent, le
     * {@code JavaMailSender} ({@code spring.mail.username}) est utilisé.
     */
    private String emailVerificationFrom;

    /**
     * Active la <b>double authentification TOTP</b> (Google Authenticator, Authy…)
     * — fonctionnalité <b>optionnelle, désactivée par défaut</b> (défaut : {@code false}).
     *
     * <p>Flux : {@code POST /2fa/setup} génère un secret Base32 (+ URI
     * {@code otpauth://} pour le QR), {@code /2fa/enable} le valide par un code,
     * puis un signin pour un compte activé répond {@code twoFactorRequired=true}
     * avec un {@code twoFactorToken} éphémère au lieu des tokens —
     * {@code POST /2fa/verify} échange code + jeton contre les tokens normaux.
     * {@code /2fa/disable} désactive (code requis).</p>
     */
    private boolean twoFactorEnabled = false;

    /** Nom affiché dans l'URI {@code otpauth://} et le QR (défaut : {@code zrouga}). */
    private String twoFactorIssuer = "zrouga";

    /** Durée de vie du challenge {@code twoFactorToken} en millisecondes (défaut : 5 minutes). */
    private long twoFactorChallengeTtlMs = 300_000L;

    /**
     * Attribution {@code SameSite} des cookies d'auth — défaut {@code Lax} ;
     * valeurs possibles {@code Lax}, {@code Strict}, {@code None}.
     * {@code None} impose aussi {@code cookie-secure=true} (front sur un autre domaine) —
     * vérifié au démarrage.
     */
    private String cookieSameSite = "Lax";

    /**
     * Active la <b>révocation des access tokens</b> à la déconnexion —
     * fonctionnalité <b>optionnelle, désactivée par défaut</b> (défaut : {@code false}).
     *
     * <p>Un JWT reste valide jusqu'à son expiration même après {@code /signout} :
     * quand {@code true}, le {@code jti} du jeton présenté est ajouté à une liste
     * noire ({@link AccessTokenRevocationStore}) et le filtre le refuse, y compris
     * si un jeton volé est rejoué. Sans effet sur les jetons émis avant l'activation.</p>
     */
    private boolean revocationEnabled = false;

    /**
     * Autorise les <b>sessions concurrentes</b> (plusieurs appareils connectés) —
     * fonctionnalité <b>optionnelle, désactivée par défaut</b> (défaut : {@code false}).
     *
     * <p>Par défaut, un {@code /signin} révoque tous les refresh tokens précédents
     * de l'utilisateur (politique mono-session). Avec {@code true}, chaque
     * connexion crée une famille indépendante : mobile et desktop coexistent ;
     * {@code /signout} ne révoque que la famille de la session courante.</p>
     */
    private boolean concurrentSessionsEnabled = false;

    /**
     * Active le <b>liaison refresh token ↔ IP/User-Agent</b> — fonctionnalité
     * <b>optionnelle, désactivée par défaut</b> (défaut : {@code false}).
     *
     * <p>Quand {@code true}, un refresh présenté depuis une IP ou un User-Agent
     * différents de ceux enregistrés à la création révoque la famille entière et
     * répond {@code 403} (vol potentiel). Les jetons créés sans binding (avant
     * l'activation, ou stores personnalisés) restent utilisables.</p>
     */
    private boolean refreshBindingEnabled = false;

    public String getJwtSecret() {
        return jwtSecret;
    }

    public void setJwtSecret(String jwtSecret) {
        this.jwtSecret = jwtSecret;
    }

    public long getJwtExpirationMs() {
        return jwtExpirationMs;
    }

    public void setJwtExpirationMs(long jwtExpirationMs) {
        this.jwtExpirationMs = jwtExpirationMs;
    }

    public long getJwtRefreshExpirationMs() {
        return jwtRefreshExpirationMs;
    }

    public void setJwtRefreshExpirationMs(long jwtRefreshExpirationMs) {
        this.jwtRefreshExpirationMs = jwtRefreshExpirationMs;
    }

    public List<String> getPublicPaths() {
        return publicPaths;
    }

    public void setPublicPaths(List<String> publicPaths) {
        this.publicPaths = publicPaths;
    }

    public int getRateLimitMaxAttempts() {
        return rateLimitMaxAttempts;
    }

    public void setRateLimitMaxAttempts(int rateLimitMaxAttempts) {
        this.rateLimitMaxAttempts = rateLimitMaxAttempts;
    }

    public long getRateLimitWindowMs() {
        return rateLimitWindowMs;
    }

    public void setRateLimitWindowMs(long rateLimitWindowMs) {
        this.rateLimitWindowMs = rateLimitWindowMs;
    }

    public boolean isTrustForwardedFor() {
        return trustForwardedFor;
    }

    public void setTrustForwardedFor(boolean trustForwardedFor) {
        this.trustForwardedFor = trustForwardedFor;
    }

    public boolean isCleanupEnabled() {
        return cleanupEnabled;
    }

    public void setCleanupEnabled(boolean cleanupEnabled) {
        this.cleanupEnabled = cleanupEnabled;
    }

    public long getCleanupFixedDelayMs() {
        return cleanupFixedDelayMs;
    }

    public void setCleanupFixedDelayMs(long cleanupFixedDelayMs) {
        this.cleanupFixedDelayMs = cleanupFixedDelayMs;
    }

    public boolean isResetEnabled() {
        return resetEnabled;
    }

    public void setResetEnabled(boolean resetEnabled) {
        this.resetEnabled = resetEnabled;
    }

    public long getResetTokenExpirationMs() {
        return resetTokenExpirationMs;
    }

    public void setResetTokenExpirationMs(long resetTokenExpirationMs) {
        this.resetTokenExpirationMs = resetTokenExpirationMs;
    }

    public String getResetBaseUrl() {
        return resetBaseUrl;
    }

    public void setResetBaseUrl(String resetBaseUrl) {
        this.resetBaseUrl = resetBaseUrl;
    }

    public String getResetEmailFrom() {
        return resetEmailFrom;
    }

    public void setResetEmailFrom(String resetEmailFrom) {
        this.resetEmailFrom = resetEmailFrom;
    }

    public boolean isLockoutEnabled() {
        return lockoutEnabled;
    }

    public void setLockoutEnabled(boolean lockoutEnabled) {
        this.lockoutEnabled = lockoutEnabled;
    }

    public int getLockoutMaxAttempts() {
        return lockoutMaxAttempts;
    }

    public void setLockoutMaxAttempts(int lockoutMaxAttempts) {
        this.lockoutMaxAttempts = lockoutMaxAttempts;
    }

    public long getLockoutDurationMs() {
        return lockoutDurationMs;
    }

    public void setLockoutDurationMs(long lockoutDurationMs) {
        this.lockoutDurationMs = lockoutDurationMs;
    }

    public boolean isPasswordPolicyEnabled() {
        return passwordPolicyEnabled;
    }

    public void setPasswordPolicyEnabled(boolean passwordPolicyEnabled) {
        this.passwordPolicyEnabled = passwordPolicyEnabled;
    }

    public int getPasswordMinLength() {
        return passwordMinLength;
    }

    public void setPasswordMinLength(int passwordMinLength) {
        this.passwordMinLength = passwordMinLength;
    }

    public boolean isPasswordRequireUppercase() {
        return passwordRequireUppercase;
    }

    public void setPasswordRequireUppercase(boolean passwordRequireUppercase) {
        this.passwordRequireUppercase = passwordRequireUppercase;
    }

    public boolean isPasswordRequireLowercase() {
        return passwordRequireLowercase;
    }

    public void setPasswordRequireLowercase(boolean passwordRequireLowercase) {
        this.passwordRequireLowercase = passwordRequireLowercase;
    }

    public boolean isPasswordRequireDigit() {
        return passwordRequireDigit;
    }

    public void setPasswordRequireDigit(boolean passwordRequireDigit) {
        this.passwordRequireDigit = passwordRequireDigit;
    }

    public boolean isPasswordRequireSpecial() {
        return passwordRequireSpecial;
    }

    public void setPasswordRequireSpecial(boolean passwordRequireSpecial) {
        this.passwordRequireSpecial = passwordRequireSpecial;
    }

    public int getPasswordHistoryCount() {
        return passwordHistoryCount;
    }

    public void setPasswordHistoryCount(int passwordHistoryCount) {
        this.passwordHistoryCount = passwordHistoryCount;
    }

    public String getAuthMode() {
        return authMode;
    }

    public void setAuthMode(String authMode) {
        this.authMode = authMode;
    }

    public boolean isCookieSecure() {
        return cookieSecure;
    }

    public void setCookieSecure(boolean cookieSecure) {
        this.cookieSecure = cookieSecure;
    }

    public String getCookieSameSite() {
        return cookieSameSite;
    }

    public void setCookieSameSite(String cookieSameSite) {
        this.cookieSameSite = cookieSameSite;
    }

    public boolean isRevocationEnabled() {
        return revocationEnabled;
    }

    public void setRevocationEnabled(boolean revocationEnabled) {
        this.revocationEnabled = revocationEnabled;
    }

    public boolean isConcurrentSessionsEnabled() {
        return concurrentSessionsEnabled;
    }

    public void setConcurrentSessionsEnabled(boolean concurrentSessionsEnabled) {
        this.concurrentSessionsEnabled = concurrentSessionsEnabled;
    }

    public boolean isRefreshBindingEnabled() {
        return refreshBindingEnabled;
    }

    public void setRefreshBindingEnabled(boolean refreshBindingEnabled) {
        this.refreshBindingEnabled = refreshBindingEnabled;
    }

    public boolean isEmailVerificationEnabled() {
        return emailVerificationEnabled;
    }

    public void setEmailVerificationEnabled(boolean emailVerificationEnabled) {
        this.emailVerificationEnabled = emailVerificationEnabled;
    }

    public String getEmailVerificationBaseUrl() {
        return emailVerificationBaseUrl;
    }

    public void setEmailVerificationBaseUrl(String emailVerificationBaseUrl) {
        this.emailVerificationBaseUrl = emailVerificationBaseUrl;
    }

    public long getEmailVerificationTokenTtlMs() {
        return emailVerificationTokenTtlMs;
    }

    public void setEmailVerificationTokenTtlMs(long emailVerificationTokenTtlMs) {
        this.emailVerificationTokenTtlMs = emailVerificationTokenTtlMs;
    }

    public String getEmailVerificationFrom() {
        return emailVerificationFrom;
    }

    public void setEmailVerificationFrom(String emailVerificationFrom) {
        this.emailVerificationFrom = emailVerificationFrom;
    }

    public boolean isTwoFactorEnabled() {
        return twoFactorEnabled;
    }

    public void setTwoFactorEnabled(boolean twoFactorEnabled) {
        this.twoFactorEnabled = twoFactorEnabled;
    }

    public String getTwoFactorIssuer() {
        return twoFactorIssuer;
    }

    public void setTwoFactorIssuer(String twoFactorIssuer) {
        this.twoFactorIssuer = twoFactorIssuer;
    }

    public long getTwoFactorChallengeTtlMs() {
        return twoFactorChallengeTtlMs;
    }

    public void setTwoFactorChallengeTtlMs(long twoFactorChallengeTtlMs) {
        this.twoFactorChallengeTtlMs = twoFactorChallengeTtlMs;
    }
}
