package zrouga.spring.security.payload;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Requête de {@code POST /api/auth/2fa/enable} et {@code /2fa/disable}.
 *
 * @param code code TOTP à 6 chiffres
 */
public record TwoFactorCodeRequest(
        @NotBlank @Pattern(regexp = "\\d{6}", message = "must be a 6-digit code") String code) {
}
