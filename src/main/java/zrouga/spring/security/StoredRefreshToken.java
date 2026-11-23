package zrouga.spring.security;

import java.time.Instant;

/**
 * Refresh token côté serveur.
 *
 * @param token      jeton brut (transmis au client — jamais stocké tel quel en base,
 *                   la persistance ne garde que son hash SHA-256)
 * @param userId     identifiant du propriétaire
 * @param expiryDate date d'expiration
 * @param revoked    {@code true} après rotation/révocation — sa lecture = détection de
 *                   réutilisation (vol potentiel)
 */
public record StoredRefreshToken(String token, long userId, Instant expiryDate, boolean revoked) {
}
