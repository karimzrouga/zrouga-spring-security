package zrouga.spring.security.payload;

import jakarta.validation.constraints.NotBlank;

/**
 * Requête de {@code POST /api/auth/verify-email}.
 *
 * @param token jeton reçu dans l'e-mail de vérification
 */
public record VerifyEmailRequest(@NotBlank String token) {
}
