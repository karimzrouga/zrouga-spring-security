package zrouga.spring.security.event;

/**
 * Émis quand un compte vient d'être verrouillé ({@code lockout-enabled},
 * seuil d'échecs atteint) — utile pour l'audit et les alertes.
 *
 * @param email e-mail verrouillé
 * @param ip    IP de la tentative en échec
 */
public record LockoutEvent(String email, String ip) {
}
