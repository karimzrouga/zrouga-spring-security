package zrouga.spring.security;

import org.springframework.beans.factory.ObjectProvider;

import io.jsonwebtoken.Claims;

/**
 * Façade de révocation des access tokens ({@code revocation-enabled}) : sans
 * effet si la fonctionnalité est désactivée, donc utilisable en toute sécurité
 * dans le filtre et la déconnexion sans condition supplémentaire.
 */
public final class AccessTokenRevocation {

    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AccessTokenRevocation.class);

    private final boolean enabled;
    private final AccessTokenRevocationStore store;

    public AccessTokenRevocation(ZrougaSecurityProperties properties,
            ObjectProvider<AccessTokenRevocationStore> storeProvider) {
        this(properties.isRevocationEnabled(), storeProvider.getIfAvailable());
    }

    private AccessTokenRevocation(boolean enabled, AccessTokenRevocationStore store) {
        this.enabled = enabled;
        this.store = store;
        if (enabled && store == null) {
            logger.warn("zrouga.security.revocation-enabled=true mais aucun bean AccessTokenRevocationStore "
                    + "disponible : la révocation des access tokens est inopérante.");
        }
    }

    /** Instance inerte (révocation désactivée) — usage du constructeur historique du filtre. */
    public static AccessTokenRevocation disabled() {
        return new AccessTokenRevocation(false, null);
    }

    /**
     * Révoque le jeton porté par les claims (signout) jusqu'à son expiration.
     * Sans effet si la révocation est désactivée.
     */
    public void revoke(Claims claims) {
        if (enabled && store != null && claims != null && claims.getId() != null && claims.getExpiration() != null) {
            store.revoke(claims.getId(), claims.getExpiration().toInstant());
        }
    }

    /**
     * @return {@code true} si le jeton (claim {@code jti}) a été révoqué — le
     *         filtre doit alors refuser l'authentification
     */
    public boolean isRevoked(String jti) {
        return enabled && store != null && jti != null && store.isRevoked(jti);
    }

    public boolean isEnabled() {
        return enabled;
    }
}
