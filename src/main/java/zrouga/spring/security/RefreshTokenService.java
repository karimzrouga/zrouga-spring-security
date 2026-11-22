package zrouga.spring.security;

import java.time.Instant;
import java.util.Optional;

import zrouga.spring.security.exception.TokenRefreshException;

public class RefreshTokenService {

    private final RefreshTokenStore refreshTokenStore;
    private final long refreshTokenDurationMs;

    public RefreshTokenService(RefreshTokenStore refreshTokenStore, ZrougaSecurityProperties properties) {
        this.refreshTokenStore = refreshTokenStore;
        this.refreshTokenDurationMs = properties.getJwtRefreshExpirationMs();
    }

    public Optional<StoredRefreshToken> findByToken(String token) {
        return refreshTokenStore.findByToken(token);
    }

    public StoredRefreshToken createRefreshToken(AuthUser user) {
        return refreshTokenStore.save(user.getId(), Instant.now().plusMillis(refreshTokenDurationMs));
    }

    public StoredRefreshToken verifyExpiration(StoredRefreshToken token) {
        if (token.expiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenStore.deleteByToken(token.token());
            throw new TokenRefreshException("Refresh token was expired. Please make a new signin request");
        }
        return token;
    }

    /**
     * Révoque un refresh token (utilisé lors de la rotation).
     *
     * @param token la valeur du jeton à révoquer
     */
    public void revoke(String token) {
        refreshTokenStore.deleteByToken(token);
    }

    public int deleteByUserId(Long userId) {
        return refreshTokenStore.deleteByUserId(userId);
    }
}
