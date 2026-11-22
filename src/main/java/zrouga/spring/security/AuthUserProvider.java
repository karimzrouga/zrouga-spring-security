package zrouga.spring.security;

import java.util.List;
import java.util.Optional;

/**
 * Pont obligatoire entre ce starter et les utilisateurs du projet hôte.
 *
 * <p>Le projet hôte implémente cette interface (typiquement en s'appuyant sur son
 * propre repository) et déclare le résultat comme bean Spring. Sans bean
 * {@code AuthUserProvider}, le démarrage de l'application échoue avec un message explicite.</p>
 */
public interface AuthUserProvider {

    /** Message d'erreur affiché au démarrage quand aucun bean {@link AuthUserProvider} est déclaré. */
    String MISSING_BEAN_MESSAGE = "zrouga.spring.security : aucun bean AuthUserProvider déclaré. "
            + "Implémentez zrouga.spring.security.AuthUserProvider et déclarez-la comme @Component ou @Bean.";

    /**
     * Recherche un utilisateur par son adresse e-mail.
     *
     * @param email adresse e-mail de l'utilisateur
     * @return l'utilisateur trouvé, ou {@link Optional#empty()}
     */
    Optional<AuthUser> findByEmail(String email);

    /**
     * Recherche un utilisateur par son identifiant.
     *
     * @param id identifiant de l'utilisateur
     * @return l'utilisateur trouvé, ou {@link Optional#empty()}
     */
    Optional<AuthUser> findById(Long id);
}
