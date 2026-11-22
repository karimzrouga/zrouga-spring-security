package zrouga.spring.security.ratelimit;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import zrouga.spring.security.ZrougaSecurityProperties;
import zrouga.spring.security.exception.RateLimitException;

/**
 * Limiteur de tentatives en mémoire : fenêtre glissante fixe par clé (e-mail).
 */
public class InMemoryLoginRateLimiter implements LoginRateLimiter {

    private static final int MAX_TRACKED_KEYS = 10_000;

    private record Attempts(int count, Instant firstAttempt) {
    }

    private final int maxAttempts;

    private final long windowMs;

    private final Map<String, Attempts> attempts = new ConcurrentHashMap<>();

    public InMemoryLoginRateLimiter(ZrougaSecurityProperties properties) {
        this.maxAttempts = Math.max(1, properties.getRateLimitMaxAttempts());
        this.windowMs = Math.max(1000L, properties.getRateLimitWindowMs());
    }

    @Override
    public void check(String key) {
        Attempts current = attempts.get(key);
        if (current == null || current.count() < maxAttempts) {
            return;
        }
        Instant now = Instant.now();
        if (now.isBefore(current.firstAttempt().plusMillis(windowMs))) {
            throw new RateLimitException(
                    "Trop de tentatives de connexion. Réessayez dans quelques minutes.");
        }
        attempts.remove(key, current);
    }

    @Override
    public void recordFailure(String key) {
        Instant now = Instant.now();
        if (attempts.size() >= MAX_TRACKED_KEYS) {
            attempts.entrySet()
                    .removeIf(entry -> now.isAfter(entry.getValue().firstAttempt().plusMillis(windowMs)));
        }
        attempts.compute(key, (k, current) -> {
            if (current == null || now.isAfter(current.firstAttempt().plusMillis(windowMs))) {
                return new Attempts(1, now);
            }
            return new Attempts(current.count() + 1, current.firstAttempt());
        });
    }

    @Override
    public void reset(String key) {
        attempts.remove(key);
    }
}
