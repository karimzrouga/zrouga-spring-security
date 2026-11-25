package zrouga.spring.security;

import java.util.List;

/**
 * Historique des mots de passe précédents d'un compte — anti-réutilisation à la
 * réinitialisation ({@code zrouga.security.password-history-count}, sous
 * {@code password-policy-enabled=true}).
 *
 * <p>Implémenté par défaut en mémoire ({@link InMemoryPasswordHistoryStore}) : l'historique
 * est perdu au redémarrage (le mot de passe <b>courant</b>, hashé par le projet hôte, reste
 * toujours vérifié). Pour le persister, déclarez votre propre bean
 * {@code PasswordHistoryStore} — l'autoconfiguration recule.</p>
 */
public interface PasswordHistoryStore {

    /**
     * Hashs des mots de passe précédents du compte, du plus ancien au plus récent
     * (le mot de passe courant n'en fait pas partie).
     *
     * @param email e-mail du compte
     * @return liste non nulle (vide si aucun historique)
     */
    List<String> find(String email);

    /**
     * Ajoute le hash du mot de passe qui vient d'être remplacé, en conservant les
     * {@code maxRetained} plus récents (les plus anciens sont écartés).
     *
     * @param email            e-mail du compte
     * @param encodedPassword  hash du mot de passe sortant
     * @param maxRetained      taille maximale de l'historique (&lt;= 0 : no-op)
     */
    void record(String email, String encodedPassword, int maxRetained);

    /**
     * Oublie l'historique du compte (ex. : suppression de compte côté projet hôte).
     *
     * @param email e-mail du compte
     */
    void delete(String email);
}
