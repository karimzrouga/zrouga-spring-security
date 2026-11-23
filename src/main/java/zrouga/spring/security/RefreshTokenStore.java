package zrouga.spring.security;

import java.time.Instant;
import java.util.Optional;

/**
 * Stockage des refresh tokens. Deux implémentations fournies : JPA (jetons hashés
 * en base) et en mémoire — et cette interface permet d'en fournir une personnalisée
 * (déclarez-la comme bean).
 *
 * <p>Sémantique 2.0 : {@link #revoke(String)} est <b>atomique</b> et retourne
 * {@code false} si le jeton était déjà révoqué — c'est ce qui rend la rotation
 * sûre en concurrence et permet de détecter une réutilisation.</p>
 */
public interface RefreshTokenStore {

    /**
     * Enregistre un nouveau refresh token.
     *
     * @param userId     identifiant du propriétaire
     * @param expiryDate date d'expiration
     * @return le jeton créé (jeton brut, propriétaire, expiration, non révoqué)
     */
    StoredRefreshToken save(long userId, Instant expiryDate);

    /**
     * Recherche un jeton par sa valeur brute — y compris s'il est révoqué
     * (la lecture d'un jeton révoqué = détection de réutilisation).
     *
     * @param token le jeton brut
     * @return le jeton trouvé, ou {@link Optional#empty()}
     */
    Optional<StoredRefreshToken> findByToken(String token);

    /**
     * Révoque un jeton de façon atomique (rotation).
     *
     * @param token le jeton brut
     * @return {@code true} si ce appel a fait passer le jeton de non révoqué à révoqué,
     *         {@code false} s'il était déjà révoqué ou absent (course ou réutilisation)
     */
    boolean revoke(String token);

    /**
     * Supprime définitivement tous les jetons d'un utilisateur (déconnexion,
     * révocation de famille sur vol détecté).
     *
     * @param userId identifiant du propriétaire
     * @return le nombre de jetons supprimés
     */
    int deleteByUserId(long userId);

    /**
     * Supprime définitivement tous les jetons expirés (purge). L'implémentation par
     * défaut ne fait rien ; les implémentations fournies (JPA, mémoire) purgent réellement.
     *
     * @param now date de référence
     * @return le nombre de jetons supprimés
     */
    default int deleteExpired(Instant now) {
        return 0;
    }
}
