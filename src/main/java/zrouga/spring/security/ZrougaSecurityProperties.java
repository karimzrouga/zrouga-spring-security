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
}
