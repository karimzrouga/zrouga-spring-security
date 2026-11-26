package zrouga.spring.security;

import java.time.Instant;

/**
 * Liste noire des access tokens révoqués (optionnelle, {@code revocation-enabled}).
 *
 * <p>Un access token JWT est par nature valide jusqu'à son expiration : la
 * déconnexion classique ne peut pas l'annuler côté serveur. Ce store garde les
 * {@code jti} révoqués (signout) jusqu'à leur expiration naturelle — le filtre
 * les refuse alors même si la signature est valide.</p>
 *
 * <p>Déclarez votre propre bean pour persister (Redis, base de données) ; le
 * défaut est en mémoire.</p>
 */
public interface AccessTokenRevocationStore {

    /**
     * Révoque un access token jusqu'à son expiration.
     *
     * @param jti        identifiant unique du jeton (claim {@code jti})
     * @param expiresAt  expiration du jeton (la entrée n'a plus d'effet après)
     */
    void revoke(String jti, Instant expiresAt);

    /**
     * @param jti identifiant du jeton
     * @return {@code true} si le jeton a été révoqué et n'est pas encore expiré
     */
    boolean isRevoked(String jti);
}
