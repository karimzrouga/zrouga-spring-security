package zrouga.spring.security;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryPasswordResetTokenStore implements PasswordResetTokenStore {

    private final ConcurrentHashMap<String, StoredResetToken> tokens = new ConcurrentHashMap<>();

    @Override
    public void save(StoredResetToken token) {
        tokens.put(token.token(), token);
    }

    @Override
    public Optional<StoredResetToken> findByToken(String token) {
        return token == null ? Optional.empty() : Optional.ofNullable(tokens.get(token));
    }

    @Override
    public void consume(String token) {
        if (token != null) {
            tokens.remove(token);
        }
    }
}
