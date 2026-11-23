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
 * Envoi de l'e-mail de réinitialisation via SMTP ({@code spring.mail.*}).
 *
 * <p>Créé uniquement si {@code zrouga.security.reset-enabled=true} et aucun bean
 * {@link PasswordResetEmailSender} personnalisé n'est déclaré. Exige un bean
 * {@link JavaMailSender} (ajoutez {@code spring-boot-starter-mail} +
 * {@code spring.mail.host}) — sinon le démarrage échoue avec un message explicite.</p>
 *
 * <p>L'envoi est <b>asynchrone</b> : la réponse HTTP (toujours 200, anti-énumération)
 * n'attend pas la latence SMTP. L'expiration/jeton reste synchrone ; seul l'envoi est
 * déporté sur le {@link TaskExecutor} fourni par l'application (ou un pool daemon de
 * repli). Les erreurs SMTP sont journalisées, jamais propagées après coup.</p>
 */
public class SmtpPasswordResetEmailSender implements PasswordResetEmailSender {

    private static final Logger logger = LoggerFactory.getLogger(SmtpPasswordResetEmailSender.class);

    private final JavaMailSender mailSender;
    private final ZrougaSecurityProperties properties;
    private final String from;
    private final TaskExecutor executor;

    public SmtpPasswordResetEmailSender(
            ObjectProvider<JavaMailSender> mailSenderProvider,
            ZrougaSecurityProperties properties,
            ObjectProvider<TaskExecutor> taskExecutorProvider) {
        JavaMailSender sender = mailSenderProvider.getIfAvailable();
        if (sender == null) {
            throw new IllegalStateException(
                    "zrouga.security.reset-enabled=true : bean JavaMailSender manquant — "
                            + "ajoutez spring-boot-starter-mail et configurez spring.mail.host / spring.mail.username.");
        }
        if (properties.getResetBaseUrl() == null || properties.getResetBaseUrl().isBlank()) {
            throw new IllegalStateException(
                    "zrouga.security.reset-enabled=true : zrouga.security.reset-base-url est obligatoire "
                            + "(URL de la page de réinitialisation côté front).");
        }
        this.mailSender = sender;
        this.properties = properties;
        this.from = resolveFrom(sender, properties);
        TaskExecutor provided = taskExecutorProvider.getIfAvailable();
        this.executor = provided != null ? provided : daemonFallback();
    }

    private static TaskExecutor daemonFallback() {
        ExecutorService pool = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "zrouga-reset-mail");
            thread.setDaemon(true);
            return thread;
        });
        return pool::execute;
    }

    private static String resolveFrom(JavaMailSender sender, ZrougaSecurityProperties properties) {
        String configured = properties.getResetEmailFrom();
        if (configured != null && !configured.isBlank()) {
            return configured.trim();
        }
        if (sender instanceof JavaMailSenderImpl impl
                && impl.getUsername() != null && !impl.getUsername().isBlank()) {
            return impl.getUsername();
        }
        throw new IllegalStateException(
                "zrouga.security.reset-enabled=true : adresse expéditrice manquante — "
                        + "renseignez zrouga.security.reset-email-from ou spring.mail.username.");
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
            helper.setSubject("Réinitialisation de votre mot de passe");
            helper.setText(buildBody(rawToken));
            mailSender.send(message);
        } catch (MessagingException | RuntimeException e) {
            logger.error("Échec de l'envoi de l'e-mail de réinitialisation : {}", e.getMessage(), e);
        }
    }

    private String buildBody(String rawToken) {
        String baseUrl = properties.getResetBaseUrl();
        String separator = baseUrl.contains("?") ? "&" : "?";
        long minutes = ChronoUnit.MINUTES.between(Instant.EPOCH,
                Instant.EPOCH.plusMillis(properties.getResetTokenExpirationMs()));
        return "Bonjour,\n\n"
                + "Une réinitialisation du mot de passe a été demandée pour votre compte.\n\n"
                + "Ouvrez ce lien pour choisir un nouveau mot de passe (valable " + minutes + " minutes) :\n"
                + baseUrl + separator + "token=" + rawToken + "\n\n"
                + "Si vous n'êtes pas à l'origine de cette demande, ignorez cet e-mail.\n";
    }
}
