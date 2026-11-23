package zrouga.spring.security;

import java.time.Instant;
import java.util.Optional;

/**
 * Stockage des jetons de réinitialisation du mot de passe.
 *
 * <p>Défaut du starter : {@link InMemoryPasswordResetTokenStore} (instance unique).
 * Déclarez votre propre bean pour une persistance distribuée (Redis, table SQL, …) —
 * l'auto-config recule.</p>
 *
 * <p>Sémantique 2.0 : {@link #consume(String)} est <b>atomique</b> (usage unique) —
 * il retourne {@code false} si le jeton était déjà consommé. {@link #deleteByEmail(String)}
 * maintient un jeton actif par compte.</p>
 */
public interface PasswordResetTokenStore {

    /** Enregistre un jeton neuf. */
    void save(StoredResetToken token);

    /** Recherche un jeton, utilisé ou non. */
    Optional<StoredResetToken> findByToken(String token);

    /**
     * Consomme définitivement un jeton (usage unique) — avant toute modification
     * du mot de passe (claim first).
     *
     * @param token le jeton brut
     * @return {@code true} si ce jeton vient d'être consommé, {@code false} s'il était
     *         déjà consommé ou absent
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
     * Supprime les jetons expirés (purge). L'implémentation par défaut ne fait rien ;
     * l'implémentation mémoire purge réellement.
     *
     * @param now date de référence
     * @return le nombre de jetons supprimés
     */
    default int deleteExpired(Instant now) {
        return 0;
    }
}
