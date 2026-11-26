package zrouga.spring.security.event;

/**
 * Émis après une déconnexion ({@code POST /api/auth/signout}) — les refresh
 * tokens du compte sont révoqués (et l'access token si {@code revocation-enabled}).
 *
 * @param userId identifiant de l'utilisateur
 */
public record SignOutEvent(long userId) {
}
