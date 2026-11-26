package zrouga.spring.security;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryRefreshTokenStore implements RefreshTokenStore {

    /** Seuil au-delà duquel une purge opportuniste des expirés est lancée à chaque save. */
    private static final int MAX_TRACKED_TOKENS = 10_000;

    private final Map<String, StoredRefreshToken> tokens = new ConcurrentHashMap<>();

    @Override
    public StoredRefreshToken save(long userId, Instant expiryDate) {
        return save(userId, expiryDate, null, null);
    }

    @Override
    public StoredRefreshToken save(long userId, Instant expiryDate, String ip, String userAgent) {
        if (tokens.size() > MAX_TRACKED_TOKENS) {
            deleteExpired(Instant.now());
        }
        String raw = UUID.randomUUID().toString();
        StoredRefreshToken stored = new StoredRefreshToken(raw, userId, expiryDate, false, ip, userAgent);
        tokens.put(raw, stored);
        return stored;
    }

    @Override
    public Optional<StoredRefreshToken> findByToken(String token) {
        return token == null ? Optional.empty() : Optional.ofNullable(tokens.get(token));
    }

    @Override
    public boolean revoke(String token) {
        if (token == null) {
            return false;
        }
        StoredRefreshToken current = tokens.get(token);
        if (current == null || current.revoked()) {
            return false;
        }
        StoredRefreshToken revoked = new StoredRefreshToken(
                current.token(), current.userId(), current.expiryDate(), true, current.ip(), current.userAgent());
        return tokens.replace(token, current, revoked);
    }

    @Override
    public int deleteByUserId(long userId) {
        int deleted = 0;
        for (StoredRefreshToken stored : tokens.values()) {
            if (stored.userId() == userId && tokens.remove(stored.token(), stored)) {
                deleted++;
            }
        }
        return deleted;
    }

    @Override
    public int deleteExpired(Instant now) {
        int deleted = 0;
        for (StoredRefreshToken stored : tokens.values()) {
            if (stored.expiryDate().isBefore(now) && tokens.remove(stored.token(), stored)) {
                deleted++;
            }
        }
        return deleted;
    }
}
