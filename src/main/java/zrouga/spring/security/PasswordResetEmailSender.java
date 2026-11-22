package zrouga.spring.security;

/**
 * Envoi de l'e-mail de réinitialisation — SPI surchargeable.
 *
 * <p>Défaut du starter : {@link SmtpPasswordResetEmailSender} (SMTP via
 * {@code spring.mail.*}). Déclarez votre propre bean pour un autre transport
 * (SendGrid, API métier, console de développement, …).</p>
 */
public interface PasswordResetEmailSender {

    /**
     * Envoie l'e-mail contenant le lien de réinitialisation.
     *
     * @param email    destinataire
     * @param rawToken jeton brut à accoler à {@code zrouga.security.reset-base-url}
     */
    void send(String email, String rawToken);
}
