package zrouga.spring.security.payload;

/**
 * Corps de {@code POST /api/auth/refreshtoken}.
 *
 * <p>Le champ peut être absent (mode {@code zrouga.security.auth-mode=cookie}) :
 * le starter lit alors la cookie {@code zrouga_refresh}. S'il est vide des deux
 * côtés, la réponse est {@code 403 refresh_token_rejected}.</p>
 */
public class TokenRefreshRequest {

    private String refreshToken;

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}
