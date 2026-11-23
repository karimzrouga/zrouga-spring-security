package zrouga.spring.security.payload;

/**
 * Réponse de {@code POST /api/auth/signin}.
 *
 * @param token        access token JWT (Bearer)
 * @param type         type d'authentification ({@code Bearer})
 * @param refreshToken refresh token à présenter sur {@code /refreshtoken}
 */
public record JwtResponse(String token, String type, String refreshToken) {

    public JwtResponse(String token, String refreshToken) {
        this(token, "Bearer", refreshToken);
    }
}
