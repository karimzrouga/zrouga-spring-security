package zrouga.spring.security;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryTwoFactorSecretStore implements TwoFactorSecretStore {

    private final Map<String, StoredTwoFactorSecret> states = new ConcurrentHashMap<>();

    @Override
    public void save(String email, StoredTwoFactorSecret state) {
        if (email == null || state == null) {
            return;
        }
        states.put(key(email), state);
    }

    @Override
    public Optional<StoredTwoFactorSecret> findByEmail(String email) {
        return email == null ? Optional.empty() : Optional.ofNullable(states.get(key(email)));
    }

    @Override
    public void delete(String email) {
        if (email != null) {
            states.remove(key(email));
        }
    }

    private static String key(String email) {
        return email.toLowerCase(Locale.ROOT);
    }
}
