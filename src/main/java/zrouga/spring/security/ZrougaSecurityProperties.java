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
     * Attribution {@code SameSite} des cookies d'auth — défaut {@code Lax} ;
     * valeurs possibles {@code Lax}, {@code Strict}, {@code None}.
     * {@code None} impose aussi {@code cookie-secure=true} (front sur un autre domaine).
     */
    private String cookieSameSite = "Lax";

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
}
