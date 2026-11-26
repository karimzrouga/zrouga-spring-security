package zrouga.spring.security.event;

/**
 * Émis après une vérification d'e-mail réussie ({@code POST /api/auth/verify-email}).
 *
 * @param email e-mail vérifié
 */
public record EmailVerifiedEvent(String email) {
}
