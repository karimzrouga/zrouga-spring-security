package zrouga.spring.security;

import java.util.Optional;

/**
 * Stockage des secrets TOTP (2FA).
 *
 * <p>Défaut du starter : {@link InMemoryTwoFactorSecretStore} (instance
 * unique). Déclarez votre propre bean pour une persistance chiffrée côté
 * application (table utilisateur, Vault, …) — l'auto-config recule.</p>
 */
public interface TwoFactorSecretStore {

    /** Enregistre (ou remplace) l'état 2FA d'un compte. */
    void save(String email, StoredTwoFactorSecret state);

    /** Recherche l'état 2FA d'un compte, absent si jamais configuré. */
    Optional<StoredTwoFactorSecret> findByEmail(String email);

    /** Supprime le secret (désactivation 2FA). */
    void delete(String email);
}
