package zrouga.spring.security;

import java.time.Instant;

/**
 * Jeton de vérification d'e-mail — usage unique, durée de vie longue (24 h).
 *
 * @param token  jeton aléatoire (Base64 URL) transmis dans l'e-mail
 * @param email  compte à vérifier
 * @param expiry instant d'expiration du jeton
 */
public record StoredEmailVerificationToken(String token, String email, Instant expiry) {
}
