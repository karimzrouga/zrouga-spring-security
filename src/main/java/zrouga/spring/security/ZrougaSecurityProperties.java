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

    /** Chemins accessibles sans authentification (défaut : {@code /api/auth/**}). */
    private List<String> publicPaths = List.of("/api/auth/**");

    /** Nombre maximal de tentatives de connexion échouées avant blocage (défaut : 5). */
    private int rateLimitMaxAttempts = 5;

    /** Fenêtre de comptage des tentatives en millisecondes (défaut : 15 minutes). */
    private long rateLimitWindowMs = 900_000L;

    /** Active la purge périodique des refresh tokens expirés (défaut : désactivé). */
    private boolean cleanupEnabled = false;

    /** Intervalle de la purge des refresh tokens expirés en millisecondes (défaut : 1 heure). */
    private long cleanupFixedDelayMs = 3_600_000L;

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
}
