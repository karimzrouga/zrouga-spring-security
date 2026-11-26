package zrouga.spring.security;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.task.TaskExecutor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;

import jakarta.mail.MessagingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Envoi de l'e-mail de vérification via SMTP ({@code spring.mail.*}).
 *
 * <p>Créé uniquement si {@code zrouga.security.email-verification-enabled=true}
 * et aucun bean {@link EmailVerificationEmailSender} personnalisé n'est déclaré.
 * Exige un bean {@link JavaMailSender} — sinon le démarrage échoue avec un
 * message explicite.</p>
 *
 * <p>L'envoi est <b>asynchrone</b> : la réponse HTTP n'attend pas la latence
 * SMTP. Les erreurs SMTP sont journalisées, jamais propagées après coup.</p>
 */
public class SmtpEmailVerificationEmailSender implements EmailVerificationEmailSender {

    private static final Logger logger = LoggerFactory.getLogger(SmtpEmailVerificationEmailSender.class);

    private final JavaMailSender mailSender;
    private final ZrougaSecurityProperties properties;
    private final String from;
    private final TaskExecutor executor;

    public SmtpEmailVerificationEmailSender(
            ObjectProvider<JavaMailSender> mailSenderProvider,
            ZrougaSecurityProperties properties,
            ObjectProvider<TaskExecutor> taskExecutorProvider) {
        JavaMailSender sender = mailSenderProvider.getIfAvailable();
        if (sender == null) {
            throw new IllegalStateException(
                    "zrouga.security.email-verification-enabled=true : bean JavaMailSender manquant — "
                            + "ajoutez spring-boot-starter-mail et configurez spring.mail.host / spring.mail.username.");
        }
        if (properties.getEmailVerificationBaseUrl() == null || properties.getEmailVerificationBaseUrl().isBlank()) {
            throw new IllegalStateException(
                    "zrouga.security.email-verification-enabled=true : "
                            + "zrouga.security.email-verification-base-url est obligatoire "
                            + "(URL de la page de vérification côté front).");
        }
        this.mailSender = sender;
        this.properties = properties;
        this.from = resolveFrom(sender, properties);
        TaskExecutor provided = taskExecutorProvider.getIfAvailable();
        this.executor = provided != null ? provided : daemonFallback();
    }

    private static TaskExecutor daemonFallback() {
        ExecutorService pool = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "zrouga-verification-mail");
            thread.setDaemon(true);
            return thread;
        });
        return pool::execute;
    }

    private static String resolveFrom(JavaMailSender sender, ZrougaSecurityProperties properties) {
        String configured = properties.getEmailVerificationFrom();
        if (configured != null && !configured.isBlank()) {
            return configured.trim();
        }
        if (sender instanceof JavaMailSenderImpl impl
                && impl.getUsername() != null && !impl.getUsername().isBlank()) {
            return impl.getUsername();
        }
        throw new IllegalStateException(
                "zrouga.security.email-verification-enabled=true : adresse expéditrice manquante — "
                        + "renseignez zrouga.security.email-verification-from ou spring.mail.username.");
    }

    @Override
    public void send(String email, String rawToken) {
        executor.execute(() -> doSend(email, rawToken));
    }

    private void doSend(String email, String rawToken) {
        try {
            var message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, StandardCharsets.UTF_8.name());
            helper.setFrom(from);
            helper.setTo(email);
            helper.setSubject("Vérifiez votre adresse e-mail");
            helper.setText(buildBody(rawToken));
            mailSender.send(message);
        } catch (MessagingException | RuntimeException e) {
            logger.error("Échec de l'envoi de l'e-mail de vérification : {}", e.getMessage(), e);
        }
    }

    private String buildBody(String rawToken) {
        String baseUrl = properties.getEmailVerificationBaseUrl();
        String separator = baseUrl.contains("?") ? "&" : "?";
        long hours = ChronoUnit.HOURS.between(Instant.EPOCH,
                Instant.EPOCH.plusMillis(properties.getEmailVerificationTokenTtlMs()));
        return "Bonjour,\n\n"
                + "Merci de votre inscription — confirmez votre adresse e-mail pour activer votre compte.\n\n"
                + "Ouvrez ce lien pour vérifier votre e-mail (valable " + hours + " heures) :\n"
                + baseUrl + separator + "token=" + rawToken + "\n\n"
                + "Si vous n'êtes pas à l'origine de cette demande, ignorez cet e-mail.\n";
    }
}
