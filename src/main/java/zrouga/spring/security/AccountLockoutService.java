package zrouga.spring.security;

import zrouga.spring.security.exception.AccountLockedException;

/**
 * Verrouillage de compte après N connexions échouées — fonctionnalité <b>optionnelle</b>
 * ({@code zrouga.security.lockout-enabled=true}, désactivée par défaut).
 *
 * <p>Implémentée par défaut en mémoire ({@link InMemoryAccountLockoutService}) :
 * le verrou vit dans la JVM et disparaît au redémarrage. Pour un déploiement
 * multi-instances ou persistant, déclarez votre propre bean
 * {@code AccountLockoutService} (Redis, base de données, …) — l'autoconfiguration recule.</p>
 *
 * <p>Contrat :</p>
 * <ul>
 * <li>{@link #check(String)} lève {@link AccountLockedException} (423) si le compte est
 *     verrouillé — à appeler <b>avant</b> l'authentification ;</li>
 * <li>{@link #recordFailure(String)} compte un échec et lève elle-même
 *     {@link AccountLockedException} dès le seuil atteint ;</li>
 * <li>{@link #reset(String)} remet le compteur à zéro (connexion réussie) ;</li>
 * <li>toutes les méthodes sont no-op si le verrouillage est désactivé.</li>
 * </ul>
 */
public interface AccountLockoutService {

    /**
     * Vérifie que le compte n'est pas verrouillé.
     *
     * @param email e-mail du compte (normalisé en minuscules par l'implémentation)
     * @throws AccountLockedException si le compte est verrouillé (423)
     */
    void check(String email);

    /**
     * Enregistre une connexion échouée.
     *
     * @param email e-mail du compte
     * @throws AccountLockedException si ce troisième+ échec atteint le seuil —
     *         le compte est alors verrouillé pour la durée configurée
     */
    void recordFailure(String email);

    /**
     * Remet le compteur du compte à zéro (connexion réussie, ou déverrouillage manuel).
     *
     * @param email e-mail du compte
     */
    void reset(String email);
}
