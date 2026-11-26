package zrouga.spring.security.event;

/**
 * Émis après une inscription réussie ({@code POST /api/auth/signup}).
 *
 * @param email e-mail inscrit
 * @param ip    IP du client
 */
public record SignUpEvent(String email, String ip) {
}
