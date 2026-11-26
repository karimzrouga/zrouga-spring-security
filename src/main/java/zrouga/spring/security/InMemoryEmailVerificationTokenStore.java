package zrouga.spring.security;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryEmailVerificationTokenStore implements EmailVerificationTokenStore {

    private final ConcurrentHashMap<String, StoredEmailVerificationToken> tokens = new ConcurrentHashMap<>();

    /** Index secondaire e-mail → jetons actifs (évite de scanner la table). */
    private final ConcurrentHashMap<String, Set<String>> tokensByEmail = new ConcurrentHashMap<>();

    @Override
    public void save(StoredEmailVerificationToken token) {
        tokens.put(token.token(), token);
        tokensByEmail.computeIfAbsent(token.email(), k -> ConcurrentHashMap.newKeySet()).add(token.token());
    }

    @Override
    public Optional<StoredEmailVerificationToken> findByToken(String token) {
        return token == null ? Optional.empty() : Optional.ofNullable(tokens.get(token));
    }

    @Override
    public boolean consume(String token) {
        if (token == null) {
            return false;
        }
        StoredEmailVerificationToken removed = tokens.remove(token);
        if (removed == null) {
            return false;
        }
        Set<String> byEmail = tokensByEmail.get(removed.email());
        if (byEmail != null) {
            byEmail.remove(token);
            if (byEmail.isEmpty()) {
                tokensByEmail.remove(removed.email(), byEmail);
            }
        }
        return true;
    }

    @Override
    public int deleteByEmail(String email) {
        if (email == null) {
            return 0;
        }
        Set<String> keys = tokensByEmail.remove(email);
        if (keys == null) {
            return 0;
        }
        int deleted = 0;
        for (String key : keys) {
            if (tokens.remove(key) != null) {
                deleted++;
            }
        }
        return deleted;
    }

    @Override
    public int deleteExpired(Instant now) {
        int deleted = 0;
        for (StoredEmailVerificationToken token : tokens.values()) {
            if (token.expiry().isBefore(now) && consume(token.token())) {
                deleted++;
            }
        }
        return deleted;
    }
}
