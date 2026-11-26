package zrouga.spring.security.payload;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Requête de {@code POST /api/auth/2fa/verify}.
 *
 * @param twoFactorToken challenge éphémère reçu au signin
 * @param code           code TOTP à 6 chiffres
 */
public record TwoFactorVerifyRequest(
        @NotBlank String twoFactorToken,
        @NotBlank @Pattern(regexp = "\\d{6}", message = "must be a 6-digit code") String code) {
}
