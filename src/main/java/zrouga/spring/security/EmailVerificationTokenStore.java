package zrouga.spring.security;

import java.time.Instant;
import java.util.Optional;

/**
 * Stockage des jetons de vérification d'e-mail.
 *
 * <p>Défaut du starter : {@link InMemoryEmailVerificationTokenStore} (instance
 * unique). Déclarez votre propre bean pour une persistance distribuée —
 * l'auto-config recule.</p>
 *
 * <p>Sémantique identique au reset : {@link #consume(String)} est atomique
 * (usage unique, claim first) et {@link #deleteByEmail(String)} maintient un
 * jeton actif par compte.</p>
 */
public interface EmailVerificationTokenStore {

    /** Enregistre un jeton neuf. */
    void save(StoredEmailVerificationToken token);

    /** Recherche un jeton, utilisé ou non. */
    Optional<StoredEmailVerificationToken> findByToken(String token);

    /**
     * Consomme définitivement un jeton (usage unique).
     *
     * @param token le jeton brut
     * @return {@code true} si ce jeton vient d'être consommé, {@code false} s'il
     *         était déjà consommé ou absent
     */
    boolean consume(String token);

    /**
     * Supprime tous les jetons actifs d'un compte (un seul jeton valide à la fois).
     *
     * @param email e-mail du compte
     * @return le nombre de jetons supprimés
     */
    int deleteByEmail(String email);

    /**
     * Supprime les jetons expirés (purge). L'implémentation par défaut ne fait
     * rien ; l'implémentation mémoire purge réellement.
     *
     * @param now date de référence
     * @return le nombre de jetons supprimés
     */
    default int deleteExpired(Instant now) {
        return 0;
    }
}
