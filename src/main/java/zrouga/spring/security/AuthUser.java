package zrouga.spring.security;

import java.util.List;

/**
 * Représentation minimale d'un utilisateur du projet hôte, telle que ce starter en a besoin
 * pour authentifier, émettre des jetons et autoriser les requêtes.
 *
 * <p>Implémentez-la sur votre propre entité ou sur une vue de celle-ci (record conseillé).</p>
 */
public interface AuthUser {

    /**
     * Identifiant unique de l'utilisateur (claim JWT {@code id}).
     *
     * @return l'identifiant
     */
    Long getId();

    /**
     * Adresse e-mail de l'utilisateur (sujet du JWT, identifiant de connexion).
     *
     * @return l'adresse e-mail
     */
    String getEmail();

    /**
     * Hash du mot de passe (jamais transmis tel quel : comparaison via {@code PasswordEncoder}).
     *
     * @return le hash du mot de passe
     */
    String getPassword();

    /**
     * Rôles de l'utilisateur — illimités, libres (ex. {@code ADMIN}, {@code AQP}).
     *
     * <p>Les autorités Spring Security sont construites avec le préfixe standard
     * {@code ROLE_} : utilisez {@code hasRole('ADMIN')} côté {@code @PreAuthorize}.</p>
     *
     * @return la liste des rôles (ne doit pas être {@code null})
     */
    List<String> getRoles();

    /**
     * Statut du compte : {@code true} actif, {@code false} désactivé, {@code null} ignoré (actif).
     *
     * <p>Un compte désactivé ne peut pas se connecter et ses jetons existants sont refusés.</p>
     *
     * @return le statut du compte
     */
    Boolean getStatus();
}
