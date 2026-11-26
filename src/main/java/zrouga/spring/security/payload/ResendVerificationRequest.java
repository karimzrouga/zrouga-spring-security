package zrouga.spring.security.payload;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Requête de {@code POST /api/auth/resend-verification}.
 *
 * @param email e-mail du compte à (re)vérifier
 */
public record ResendVerificationRequest(@NotBlank @Email String email) {
}
