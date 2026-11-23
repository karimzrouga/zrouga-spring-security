package zrouga.spring.security.ratelimit;

/**
 * Limiteur de tentatives (anti-bruteforce) sur les endpoints publics
 * {@code signin}, {@code signup}, {@code forgot-password} et {@code reset-password}.
 *
 * <p>Sémantique 2.0 : {@link #check(String)} <b>réserve</b> une tentative — il est
 * incrémenté à chaque appel et lève {@link zrouga.spring.security.exception.RateLimitException}
 * (HTTP 429) dès que le seuil est dépassé. Aucun appel séparé d'enregistrement
 * d'échec n'est nécessaire : l'échec est la réponse par défaut.</p>
 *
 * <p>Implémentez cette interface pour fournir votre propre stratégie
 * (base de données, Redis, etc.) et déclarez-la comme bean : l'implémentation
 * en mémoire par défaut est alors remplacée.</p>
 */
public interface LoginRateLimiter {

    /**
     * Réserve une tentative pour la clé métier (e-mail) et vérifie le seuil.
     *
     * @param key clé de limitation, typiquement {@code signin:email:<email>}
     * @throws zrouga.spring.security.exception.RateLimitException si le seuil est atteint (HTTP 429)
     */
    void check(String key);

    /**
     * Réserve une tentative pour la clé IP (seuil relevé, ex. ×10) et vérifie le seuil.
     *
     * @param key clé de limitation, typiquement {@code signin:ip:<ip>}
     * @throws zrouga.spring.security.exception.RateLimitException si le seuil est atteint (HTTP 429)
     */
    void checkIp(String key);

    /**
     * Réinitialise le compteur de la clé (connexion réussie).
     *
     * @param key clé de limitation
     */
    void reset(String key);
}
