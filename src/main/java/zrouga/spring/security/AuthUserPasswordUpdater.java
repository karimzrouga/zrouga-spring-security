package zrouga.spring.security;

/**
 * Pont d'écriture pour la réinitialisation du mot de passe — implémentez-le dans
 * le projet hôte pour mettre à jour réellement le mot de passe (votre entité, votre table).
 *
 * <p>Requis uniquement quand {@code zrouga.security.reset-enabled=true} : sans bean,
 * le démarrage échoue avec un message explicite.</p>
 */
public interface AuthUserPasswordUpdater {

    /**
     * Enregistre le nouveau mot de passe (déjà hashé par le {@code PasswordEncoder} du starter).
     *
     * @param email            compte concerné par la réinitialisation
     * @param encodedPassword  hash BCrypt du nouveau mot de passe, prêt à stocker
     */
    void updatePassword(String email, String encodedPassword);
}
