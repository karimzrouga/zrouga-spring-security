package zrouga.spring.security;

/**
 * Marque un compte comme <b>e-mail vérifié</b> — SPI à implémenter côté
 * application (la table utilisateur est la vôtre).
 *
 * <p>Requis uniquement si {@code zrouga.security.email-verification-enabled=true}
 * — le démarrage échoue avec un message explicite si le bean manque.</p>
 */
public interface AuthUserEmailVerifier {

    /** Message du bean manquant (utilisé par la validation au démarrage). */
    String MISSING_BEAN_MESSAGE = "zrouga.security.email-verification-enabled=true : aucun bean "
            + "AuthUserEmailVerifier déclaré. Implémentez zrouga.spring.security.AuthUserEmailVerifier "
            + "et déclarez-la comme @Component ou @Bean.";

    /**
     * Marque l'e-mail du compte comme vérifié (appelé après consommation du jeton).
     *
     * @param email e-mail vérifié
     */
    void verifyEmail(String email);
}
