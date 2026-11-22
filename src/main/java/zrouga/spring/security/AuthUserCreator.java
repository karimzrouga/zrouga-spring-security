package zrouga.spring.security;

/**
 * Pont d'écriture pour l'inscription — implémentez-le dans le projet hôte pour
 * créer réellement un nouvel utilisateur (votre entité, votre table).
 *
 * <p>Le starter hash le mot de passe avec le {@code PasswordEncoder} en place
 * et transmet le hash : ne jamais ré-encoder ni stocker en clair.</p>
 *
 * <p><b>Les rôles ne viennent jamais de la requête</b> : c'est cette implémentation
 * qui décide du rôle attribué à l'inscription (rôle par défaut, validation manuelle, etc.).
 * Cela évite l'élévation de privilèges (auto-inscription en ADMIN).</p>
 */
public interface AuthUserCreator {

    /**
     * Crée un nouvel utilisateur lors de {@code POST /api/auth/signup}.
     *
     * @param email            adresse e-mail de l'inscription (non utilisée ailleurs)
     * @param encodedPassword  hash du mot de passe, déjà encodé par le {@code PasswordEncoder}
     */
    void create(String email, String encodedPassword);
}
