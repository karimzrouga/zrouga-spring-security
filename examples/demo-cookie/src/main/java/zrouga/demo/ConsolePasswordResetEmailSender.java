package zrouga.demo;

import zrouga.spring.security.PasswordResetEmailSender;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Expéditeur de réinitialisation de démonstration : imprime le jeton dans le log
 * au lieu d'envoyer un e-mail SMTP — permet de tester le flux complet
 * forgot/reset sans serveur mail (l'application remplace
 * {@code SmtpPasswordResetEmailSender} via la SPI {@link PasswordResetEmailSender}).
 */
@Component
public class ConsolePasswordResetEmailSender implements PasswordResetEmailSender {

    private static final Logger log = LoggerFactory.getLogger(ConsolePasswordResetEmailSender.class);

    @Override
    public void send(String email, String rawToken) {
        log.info("RESET-TOKEN email={} token={}", email, rawToken);
    }
}
