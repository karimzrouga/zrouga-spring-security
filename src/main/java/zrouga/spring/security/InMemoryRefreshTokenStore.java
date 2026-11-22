package zrouga.spring.security;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryRefreshTokenStore implements RefreshTokenStore {

    private final Map<String, StoredRefreshToken> tokens = new ConcurrentHashMap<>();

    @Override
    public StoredRefreshToken save(long userId, Instant expiryDate) {
        StoredRefreshToken stored = new StoredRefreshToken(UUID.randomUUID().toString(), userId, expiryDate);
        tokens.put(stored.token(), stored);
        return stored;
    }

    @Override
    public Optional<StoredRefreshToken> findByToken(String token) {
        return Optional.ofNullable(tokens.get(token));
    }

    @Override
    public void deleteByToken(String token) {
        tokens.remove(token);
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
