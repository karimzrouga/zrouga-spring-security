package zrouga.spring.security.event;

/**
 * Émis après une rotation réussie du refresh token ({@code POST /api/auth/refreshtoken}).
 *
 * @param userId identifiant du propriétaire du jeton
 */
public record TokenRefreshedEvent(long userId) {
}
