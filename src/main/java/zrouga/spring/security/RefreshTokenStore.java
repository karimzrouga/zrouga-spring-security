package zrouga.spring.security;

import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenStore {

    StoredRefreshToken save(long userId, Instant expiryDate);

    Optional<StoredRefreshToken> findByToken(String token);

    void deleteByToken(String token);

    int deleteByUserId(long userId);
}
