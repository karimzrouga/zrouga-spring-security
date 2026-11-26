package zrouga.spring.security;

/**
 * État TOTP d'un compte — secret Base32 et drapeau d'activation.
 *
 * @param secret  secret Base32 (jamais renvoyé après activation sauf via setup)
 * @param enabled {@code true} une fois le code de confirmation validé
 *                ({@code /2fa/enable}) — c'est lui qui déclenche le challenge
 *                au signin
 */
public record StoredTwoFactorSecret(String secret, boolean enabled) {
}
