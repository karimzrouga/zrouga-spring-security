package zrouga.spring.security;

import java.time.Instant;
import java.util.Optional;

/**
 * Stockage des refresh tokens. Trois implémentations fournies : JPA, en mémoire,
 * et cette interface permet d'en fournir une personnalisée (déclarezz-la comme bean).
 */
public interface RefreshTokenStore {

    /**
     * Enregistre un nouveau refresh token.
     *
     * @param userId     identifiant du propriétaire
     * @param expiryDate date d'expiration
     * @return le jeton stocké (jeton brut, propriétaire, expiration)
     */
    StoredRefreshToken save(long userId, Instant expiryDate);

    /**
     * Recherche un jeton par sa valeur.
     *
     * @param token la valeur du jeton
     * @return le jeton trouvé, ou {@link Optional#empty()}
     */
    Optional<StoredRefreshToken> findByToken(String token);

    /**
     * Supprime un jeton (rotation, expiration).
     *
     * @param token la valeur du jeton
     */
    void deleteByToken(String token);

    /**
     * Supprime tous les jetons d'un utilisateur (déconnexion, nouvelle connexion).
     *
     * @param userId identifiant du propriétaire
     * @return le nombre de jetons supprimés
     */
    int deleteByUserId(long userId);

    /**
     * Supprime tous les jetons expirés (purge). L'implémentation par défaut ne fait rien ;
     * les implémentations fournies (JPA, mémoire) purge réellement.
     *
     * @param now date de référence
     * @return le nombre de jetons supprimés
     */
    default int deleteExpired(Instant now) {
        return 0;
    }
}
