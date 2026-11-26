package zrouga.spring.security.event;

/**
 * Émis après une connexion réussie ({@code POST /api/auth/signin}).
 *
 * @param email  e-mail connecté
 * @param userId identifiant de l'utilisateur
 * @param ip     IP du client
 */
public record SignInEvent(String email, long userId, String ip) {
}
