package zrouga.spring.security;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Liste noire en mémoire : plafond de 10 000 jetons suivis avec purge des
 * expirés (un jeton expiré est de toute façon refusé par le parseur — l'entrée
 * n'a plus d'effet).
 */
public class InMemoryAccessTokenRevocationStore implements AccessTokenRevocationStore {

    /** Seuil au-delà duquel une purge opportuniste des expirés est lancée. */
    private static final int MAX_TRACKED_TOKENS = 10_000;

    private final Map<String, Instant> revoked = new ConcurrentHashMap<>();

    @Override
    public void revoke(String jti, Instant expiresAt) {
        if (jti == null || expiresAt == null) {
            return;
        }
        if (revoked.size() >= MAX_TRACKED_TOKENS) {
            Instant now = Instant.now();
            revoked.entrySet().removeIf(entry -> entry.getValue().isBefore(now));
        }
        revoked.put(jti, expiresAt);
    }

    @Override
    public boolean isRevoked(String jti) {
        if (jti == null) {
            return false;
        }
        Instant expiresAt = revoked.get(jti);
        if (expiresAt == null) {
            return false;
        }
        if (expiresAt.isBefore(Instant.now())) {
            revoked.remove(jti, expiresAt);
            return false;
        }
        return true;
    }
}
