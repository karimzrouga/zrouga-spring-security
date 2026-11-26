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

    public StoredRefreshToken createRefreshToken(long userId) {
        return createRefreshToken(userId, null, null);
    }

    public StoredRefreshToken createRefreshToken(long userId, String ip, String userAgent) {
        return refreshTokenStore.save(userId, Instant.now().plusMillis(refreshTokenDurationMs), ip, userAgent);
    }

    public StoredRefreshToken verifyExpiration(StoredRefreshToken token) {
        if (token.expiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenStore.revoke(token.token());
            throw new TokenRefreshException("Refresh token was expired. Please make a new signin request");
        }
        return token;
    }

    /**
     * Révoque de façon atomique un refresh token (rotation).
     *
     * @param token la valeur du jeton à révoquer
     * @return {@code false} s'il était déjà révoqué (réutilisation détectée)
     */
    public boolean revoke(String token) {
        return refreshTokenStore.revoke(token);
    }

    public int deleteByUserId(Long userId) {
        return refreshTokenStore.deleteByUserId(userId);
    }

    public int deleteExpired(Instant now) {
        return refreshTokenStore.deleteExpired(now);
    }
}
