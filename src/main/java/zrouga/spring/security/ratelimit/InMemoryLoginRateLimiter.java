package zrouga.spring.security.ratelimit;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import zrouga.spring.security.ZrougaSecurityProperties;
import zrouga.spring.security.exception.RateLimitException;

/**
 * Limiteur de tentatives en mémoire : fenêtre glissante fixe par clé, réservation
 * atomique ({@link Map#compute}) — aucune tentative n'échappe à la concurrence.
 */
public class InMemoryLoginRateLimiter implements LoginRateLimiter {

    private static final int MAX_TRACKED_KEYS = 10_000;

    /** Seuil IP relevé : absorbe le NAT (plusieurs comptes derrière une même IP). */
    private static final long IP_LIMIT_MULTIPLIER = 10;

    private static final String LIMIT_MESSAGE = "Too many attempts. Try again in a few minutes.";

    private record Attempts(int count, Instant firstAttempt) {
    }

    private final long maxAttempts;

    private final long ipMaxAttempts;

    private final long windowMs;

    private final Map<String, Attempts> attempts = new ConcurrentHashMap<>();

    private volatile Instant nextEvictionCheck = Instant.EPOCH;

    public InMemoryLoginRateLimiter(ZrougaSecurityProperties properties) {
        this.maxAttempts = Math.max(1, properties.getRateLimitMaxAttempts());
        this.ipMaxAttempts = Math.max(1, this.maxAttempts * IP_LIMIT_MULTIPLIER);
        this.windowMs = Math.max(1000L, properties.getRateLimitWindowMs());
    }

    @Override
    public void check(String key) {
        reserve(key, maxAttempts);
    }

    @Override
    public void checkIp(String key) {
        reserve(key, ipMaxAttempts);
    }

    @Override
    public void reset(String key) {
        attempts.remove(key);
    }

    private void reserve(String key, long limit) {
        Instant now = Instant.now();
        evictIfNeeded(now);
        Attempts reserved = attempts.compute(key, (k, current) -> {
            if (current == null || now.isAfter(current.firstAttempt().plusMillis(windowMs))) {
                return new Attempts(1, now);
            }
            return new Attempts(current.count() + 1, current.firstAttempt());
        });
        if (reserved.count() > limit) {
            throw new RateLimitException(LIMIT_MESSAGE);
        }
    }

    private void evictIfNeeded(Instant now) {
        if (attempts.size() < MAX_TRACKED_KEYS || now.isBefore(nextEvictionCheck)) {
            return;
        }
        nextEvictionCheck = now.plusMillis(windowMs);
        attempts.entrySet()
                .removeIf(entry -> now.isAfter(entry.getValue().firstAttempt().plusMillis(windowMs)));
    }
}
