package zrouga.spring.security.event;

/**
 * Émis quand une connexion échoue (mauvais mot de passe, compte inconnu ou
 * inactif) — utile pour les métriques d'échec et l'alerting.
 *
 * @param email e-mail tenté
 * @param ip    IP du client
 */
public record SignInFailedEvent(String email, String ip) {
}
