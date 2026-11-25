package zrouga.spring.security;

import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import zrouga.spring.security.exception.AccountLockedException;

/**
 * Verrouillage de compte en mémoire : compteur d'échecs par e-mail (minuscules),
 * verrou à durée fixe, mises à jour atomiques ({@link Map#compute}).
 *
 * <p>Vieillissement : un verrou expiré <b>et</b> un compteur d'échecs plus ancien que
 * {@code lockout-duration-ms} sont purgés — après expiration, l'utilisateur repart de zéro.
 * Plafond de {@value #MAX_TRACKED_KEYS} comptes suivis avec purge des entrées expirées
 * (limite le coût mémoire face à un flux d'e-mails distincts).</p>
 */
public class InMemoryAccountLockoutService implements AccountLockoutService {

    private static final int MAX_TRACKED_KEYS = 10_000;

    private static final String LOCK_MESSAGE =
            "Account locked due to too many failed sign-in attempts. Try again in %d minute(s).";

    /** État d'un compte : échecs depuis la dernière remise à zéro, dernier échec, verrou éventuel. */
    private record LockoutState(int failures, Instant lastFailure, Instant lockedUntil) {
    }

    private final boolean enabled;
    private final int maxAttempts;
    private final long durationMs;

    private final Map<String, LockoutState> states = new ConcurrentHashMap<>();

    private volatile Instant nextEvictionCheck = Instant.EPOCH;

    public InMemoryAccountLockoutService(ZrougaSecurityProperties properties) {
        this.enabled = properties.isLockoutEnabled();
        this.maxAttempts = Math.max(1, properties.getLockoutMaxAttempts());
        this.durationMs = Math.max(1000L, properties.getLockoutDurationMs());
    }

    @Override
    public void check(String email) {
        if (!enabled) {
            return;
        }
        String key = key(email);
        Instant now = Instant.now();
        LockoutState state = states.get(key);
        if (state == null) {
            return;
        }
        if (state.lockedUntil() != null) {
            if (now.isBefore(state.lockedUntil())) {
                throw locked(state.lockedUntil(), now);
            }
            // Verrou expiré : remise à zéro complète du compte.
            states.remove(key, state);
            return;
        }
        // Échecs plus anciens que la fenêtre : le compteur ne doit plus les compter.
        if (now.isAfter(state.lastFailure().plusMillis(durationMs))) {
            states.remove(key, state);
        }
    }

    @Override
    public void recordFailure(String email) {
        if (!enabled) {
            return;
        }
        String key = key(email);
        Instant now = Instant.now();
        evictIfNeeded(now);
        LockoutState recorded = states.compute(key, (k, current) -> {
            if (current != null && current.lockedUntil() != null && now.isBefore(current.lockedUntil())) {
                // Course avec un verrou posé entre check() et ici : verrou ni prolongé, ni échec ajouté.
                return current;
            }
            int failures = nextFailures(current, now);
            if (failures >= maxAttempts) {
                return new LockoutState(failures, now, now.plusMillis(durationMs));
            }
            return new LockoutState(failures, now, null);
        });
        if (recorded.lockedUntil() != null && now.isBefore(recorded.lockedUntil())) {
            throw locked(recorded.lockedUntil(), now);
        }
    }

    @Override
    public void reset(String email) {
        states.remove(key(email));
    }

    /** Échecs à conserver depuis l'état courant (0 si état absent, verrou expiré ou périmé). */
    private int nextFailures(LockoutState current, Instant now) {
        if (current == null) {
            return 1;
        }
        if (current.lockedUntil() != null) {
            // Verrou expiré : repartir de zéro.
            return 1;
        }
        if (now.isAfter(current.lastFailure().plusMillis(durationMs))) {
            // Compteur périmé : repartir de zéro.
            return 1;
        }
        return current.failures() + 1;
    }

    private AccountLockedException locked(Instant lockedUntil, Instant now) {
        long minutes = Math.max(1, Math.round((lockedUntil.toEpochMilli() - now.toEpochMilli()) / 60_000.0));
        return new AccountLockedException(LOCK_MESSAGE.formatted(minutes));
    }

    private static String key(String email) {
        return email == null ? "" : email.toLowerCase(Locale.ROOT);
    }

    private void evictIfNeeded(Instant now) {
        if (states.size() < MAX_TRACKED_KEYS || now.isBefore(nextEvictionCheck)) {
            return;
        }
        nextEvictionCheck = now.plusMillis(durationMs);
        states.entrySet().removeIf(entry -> {
            LockoutState state = entry.getValue();
            if (state.lockedUntil() != null) {
                return !now.isBefore(state.lockedUntil());
            }
            return now.isAfter(state.lastFailure().plusMillis(durationMs));
        });
    }
}
