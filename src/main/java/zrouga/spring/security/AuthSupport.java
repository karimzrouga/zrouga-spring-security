package zrouga.spring.security;

import java.util.Locale;

import org.springframework.beans.factory.ObjectProvider;

/**
 * Aides partagées entre {@link AuthService} et {@link PasswordResetService}
 * (normalisation des clés de rate-limit, résolution du {@link AuthUserProvider}).
 */
final class AuthSupport {

    private AuthSupport() {
    }

    /** Clé de rate-limit normalisée : e-mail en minuscules ({@code null} → chaîne vide). */
    static String rateLimitKey(String email) {
        return email == null ? "" : email.toLowerCase(Locale.ROOT);
    }

    /** Résout le {@link AuthUserProvider} ou échoue avec un message explicite. */
    static AuthUserProvider provider(ObjectProvider<AuthUserProvider> userProvider) {
        AuthUserProvider provider = userProvider.getIfAvailable();
        if (provider == null) {
            throw new IllegalStateException(AuthUserProvider.MISSING_BEAN_MESSAGE);
        }
        return provider;
    }
}
