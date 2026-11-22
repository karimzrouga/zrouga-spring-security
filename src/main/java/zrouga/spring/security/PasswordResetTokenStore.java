package zrouga.spring.security;

import java.util.Optional;

/**
 * Stockage des jetons de réinitialisation du mot de passe.
 *
 * <p>Défaut du starter : {@link InMemoryPasswordResetTokenStore} (instance unique).
 * Déclarez votre propre bean pour une persistance distribuée (Redis, table SQL, …) —
 * l'auto-config recule.</p>
 */
public interface PasswordResetTokenStore {

    /** Enregistre un jeton neuf. */
    void save(StoredResetToken token);

    /** Recherche un jeton, utilisé ou non. */
    Optional<StoredResetToken> findByToken(String token);

    /** Consomme définitivement un jeton (usage unique — appelé après réinitialisation réussie ou jeton expiré). */
    void consume(String token);
}
