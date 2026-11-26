package zrouga.spring.security.payload;

/**
 * Réponse de {@code POST /api/auth/2fa/setup}.
 *
 * @param secret      secret Base32 à saisir manuellement dans l'authenticator
 * @param otpauthUri  URI {@code otpauth://} à encoder en QR côté front
 */
public record TwoFactorSetupResponse(String secret, String otpauthUri) {
}
