package zrouga.spring.security;

/**
 * Envoi de l'e-mail de vérification — SPI surchargeable.
 *
 * <p>Défaut du starter : {@link SmtpEmailVerificationEmailSender} (SMTP via
 * {@code spring.mail.*}). Déclarez votre propre bean pour un autre transport
 * (SendGrid, API métier, console de développement, …).</p>
 */
public interface EmailVerificationEmailSender {

    /**
     * Envoie l'e-mail contenant le lien de vérification.
     *
     * @param email    destinataire
     * @param rawToken jeton brut à accoler à {@code zrouga.security.email-verification-base-url}
     */
    void send(String email, String rawToken);
}
