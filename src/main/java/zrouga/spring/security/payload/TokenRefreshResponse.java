package zrouga.spring.security.payload;

/**
 * Réponse de {@code POST /api/auth/refreshtoken} — le refresh token appelé est révoqué
 * (rotation) et remplacé.
 *
 * @param accessToken  nouvel access token
 * @param refreshToken nouveau refresh token (l'ancien est révoqué)
 * @param tokenType    type d'authentification ({@code Bearer})
 */
public record TokenRefreshResponse(String accessToken, String refreshToken, String tokenType) {

    public TokenRefreshResponse(String accessToken, String refreshToken) {
        this(accessToken, refreshToken, "Bearer");
    }
}
