package zrouga.spring.security.ratelimit;

/**
 * Limiteur de tentatives de connexion (anti-bruteforce) sur {@code POST /api/auth/signin}.
 *
 * <p>Implémentez cette interface pour fournir votre propre stratégie
 * (base de données, Redis, etc.) et déclarez-la comme bean : l'implémentation
 * en mémoire par défaut est alors remplacée.</p>
 */
public interface LoginRateLimiter {

    /**
     * Vérifie que la clé (e-mail de connexion) n'est pas bloquée.
     *
     * @param key clé de limitation, typiquement l'e-mail en minuscules
     * @throws zrouga.spring.security.exception.RateLimitException si le seuil est atteint (HTTP 429)
     */
    void check(String key);

    /**
     * Enregistre une tentative échouée pour la clé.
     *
     * @param key clé de limitation
     */
    void recordFailure(String key);

    /**
     * Réinitialise le compteur de la clé (connexion réussie).
     *
     * @param key clé de limitation
     */
    void reset(String key);
}
