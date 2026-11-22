package zrouga.spring.security;

import java.time.Instant;

/**
 * Jeton de réinitialisation du mot de passe — usage unique, durée de vie courte.
 *
 * @param token  jeton aléatoire (Base64 URL) transmis dans l'e-mail
 * @param email  compte à réinitialiser
 * @param expiry instant d'expiration du jeton
 */
public record StoredResetToken(String token, String email, Instant expiry) {
}
