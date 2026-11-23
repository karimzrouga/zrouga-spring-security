package zrouga.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.task.TaskExecutor;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;

import jakarta.mail.internet.MimeMessage;

import org.junit.jupiter.api.Test;

class SmtpPasswordResetEmailSenderTest {

    @SuppressWarnings("unchecked")
    private static <T> ObjectProvider<T> providerOf(T value) {
        ObjectProvider<T> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(value);
        return provider;
    }

    private ZrougaSecurityProperties properties() {
        ZrougaSecurityProperties properties = new ZrougaSecurityProperties();
        properties.setResetBaseUrl("https://front.test/reset");
        properties.setResetEmailFrom("noreply@test.com");
        return properties;
    }

    private JavaMailSender mailSenderReturningMessage() throws Exception {
        JavaMailSender mailSender = mock(JavaMailSender.class);
        when(mailSender.createMimeMessage()).thenReturn(new MimeMessage((jakarta.mail.Session) null));
        return mailSender;
    }

    @Test
    void envoiDelegueAuTaskExecutorFourni() throws Exception {
        JavaMailSender mailSender = mailSenderReturningMessage();
        List<Runnable> queued = new ArrayList<>();

        SmtpPasswordResetEmailSender sender = new SmtpPasswordResetEmailSender(
                providerOf(mailSender), properties(), providerOf((TaskExecutor) queued::add));

        sender.send("user@test.com", "jeton-secret");

        // L'envoi n'a pas encore eu lieu : la requête HTTP n'attend pas le SMTP.
        assertThat(queued).hasSize(1);
        verify(mailSender, never()).send(any(MimeMessage.class));

        queued.get(0).run();
        verify(mailSender).send(any(MimeMessage.class));
    }

    @Test
    void echecSmtpJamaisPropage() throws Exception {
        JavaMailSender mailSender = mock(JavaMailSender.class);
        when(mailSender.createMimeMessage()).thenThrow(new MailException("smtp down") {
        });

        SmtpPasswordResetEmailSender sender = new SmtpPasswordResetEmailSender(
                providerOf(mailSender), properties(), providerOf((TaskExecutor) Runnable::run));

        assertThatCode(() -> sender.send("user@test.com", "jeton"))
                .doesNotThrowAnyException();
    }

    @Test
    void repliDaemonSansTaskExecutor() throws Exception {
        JavaMailSender mailSender = mailSenderReturningMessage();

        assertThatCode(() -> new SmtpPasswordResetEmailSender(
                providerOf(mailSender), properties(), providerOf(null)))
                .doesNotThrowAnyException();
    }

    @Test
    void purgeDesJetonsResetExpires() {
        InMemoryPasswordResetTokenStore resetStore = new InMemoryPasswordResetTokenStore();
        resetStore.save(new StoredResetToken("expire", "a@test.com", Instant.now().minusSeconds(10)));
        resetStore.save(new StoredResetToken("valide", "a@test.com", Instant.now().plusSeconds(60)));

        new RefreshTokenCleanup(new InMemoryRefreshTokenStore(), resetStore).deleteExpiredTokens();

        assertThat(resetStore.findByToken("expire")).isEmpty();
        assertThat(resetStore.findByToken("valide")).isPresent();
    }
}
