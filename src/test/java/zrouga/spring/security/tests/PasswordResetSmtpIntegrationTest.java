package zrouga.spring.security.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import zrouga.spring.security.PasswordResetEmailSender;
import zrouga.spring.security.SmtpPasswordResetEmailSender;
import zrouga.spring.security.ZrougaSecurityProperties;

import com.icegreen.greenmail.util.GreenMail;
import com.icegreen.greenmail.util.ServerSetup;

import jakarta.mail.internet.MimeMessage;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.core.task.TaskExecutor;
import org.springframework.http.MediaType;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Flux complet de réinitialisation avec le <b>vrai</b> expéditeur SMTP du starter
 * (GreenMail) : l'e-mail part par SMTP, le jeton en extrait permet de réinitialiser,
 * l'ancien mot de passe ne fonctionne plus.
 */
@SpringBootTest(properties = {
        "zrouga.security.reset-enabled=true",
        "zrouga.security.reset-base-url=https://front.test/reset-password",
        "zrouga.security.reset-email-from=noreply@test.com"
})
@AutoConfigureMockMvc
class PasswordResetSmtpIntegrationTest {

    private static GreenMail greenMail;

    @DynamicPropertySource
    static void smtpPort(DynamicPropertyRegistry registry) {
        greenMail = new GreenMail(new ServerSetup(0, "127.0.0.1", ServerSetup.PROTOCOL_SMTP));
        greenMail.start();
        registry.add("test.smtp.port", () -> greenMail.getSmtp().getPort());
    }

    @AfterAll
    static void stopGreenMail() {
        greenMail.stop();
    }

    @TestConfiguration
    static class SmtpConfiguration {

        @Bean
        JavaMailSender greenMailJavaMailSender(@Value("${test.smtp.port}") int port) {
            JavaMailSenderImpl sender = new JavaMailSenderImpl();
            sender.setHost("127.0.0.1");
            sender.setPort(port);
            return sender;
        }

        /** Exécution synchrone en test : l'envoi SMTP est observé dans le test. */
        @Bean
        TaskExecutor directTaskExecutor() {
            return Runnable::run;
        }

        @Bean
        @Primary
        PasswordResetEmailSender smtpSender(
                ObjectProvider<JavaMailSender> mailSender,
                ZrougaSecurityProperties properties,
                ObjectProvider<TaskExecutor> taskExecutor) {
            return new SmtpPasswordResetEmailSender(mailSender, properties, taskExecutor);
        }
    }

    @Autowired
    private MockMvc mockMvc;

    @Test
    void forgotPuisResetParSmtpChangeLeMotDePasse() throws Exception {
        String email = "smtp-" + System.nanoTime() + "@test.com";
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"MotDePasse123\"}"))
                .andExpect(status().isCreated());

        int avant = greenMail.getReceivedMessages().length;

        mockMvc.perform(post("/api/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message")
                        .value("If the account exists, a reset email has been sent."));

        MimeMessage[] messages = greenMail.getReceivedMessages();
        assertThat(messages.length - avant).isEqualTo(1);
        MimeMessage message = messages[messages.length - 1];
        assertThat(message.getSubject()).isEqualTo("Réinitialisation de votre mot de passe");
        String body = (String) message.getContent();
        assertThat(body).contains("https://front.test/reset-password?token=");

        Matcher matcher = Pattern.compile("token=([A-Za-z0-9_-]+)").matcher(body);
        assertThat(matcher.find()).isTrue();
        String resetToken = matcher.group(1);

        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + resetToken + "\",\"password\":\"NouveauMotDePasse9\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Password has been reset successfully."));

        mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"NouveauMotDePasse9\"}"))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"MotDePasse123\"}"))
                .andExpect(status().isUnauthorized());

        // Usage unique : le même jeton ne fonctionne plus.
        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + resetToken + "\",\"password\":\"EncoreUnAutre99\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Invalid or expired reset token."));
    }

    @Test
    void forgotPasswordCompteInconnuNeEnvoieAucunMail() throws Exception {
        int avant = greenMail.getReceivedMessages().length;

        mockMvc.perform(post("/api/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"inexistant-" + System.nanoTime() + "@test.com\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message")
                        .value("If the account exists, a reset email has been sent."));

        assertThat(greenMail.getReceivedMessages().length).isEqualTo(avant);
    }

    @Test
    void resetPasswordJetonSmtpInvalideRenvoie400() throws Exception {
        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"jeton-absent\",\"password\":\"MotDePasse123\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Invalid or expired reset token."));
    }
}
