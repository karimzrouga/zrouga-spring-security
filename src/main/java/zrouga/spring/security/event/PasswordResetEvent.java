package zrouga.spring.security.event;

/**
 * Émis après une réinitialisation de mot de passe réussie
 * ({@code POST /api/auth/reset-password}) — les refresh tokens du compte sont
 * révoqués à cette occasion.
 *
 * @param email e-mail du compte réinitialisé
 */
public record PasswordResetEvent(String email) {
}
