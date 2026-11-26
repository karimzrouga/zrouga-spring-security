package zrouga.spring.security.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import zrouga.spring.security.AuthUserEmailVerifier;
import zrouga.spring.security.EmailVerificationEmailSender;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/**
 * {@code zrouga.security.email-verification-enabled=true} : jeton envoyé à
 * l'inscription, consommé par {@code /verify-email} (usage unique), renouvelable
 * par {@code /resend-verification} — sans révéler l'existence des comptes.
 */
@SpringBootTest(properties = {
        "zrouga.security.email-verification-enabled=true",
        "zrouga.security.email-verification-base-url=https://front.test/verify-email"
})
@AutoConfigureMockMvc
class EmailVerificationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private FakeVerificationSender sender;

    @Autowired
    private RecordingEmailVerifier verifier;

    @BeforeEach
    void reset() {
        sender.tokens.clear();
        verifier.emails.clear();
    }

    private void signup(String email) throws Exception {
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"MotDePasse@123\"}"))
                .andExpect(status().isCreated());
    }

    private void verifyToken(String token, int expectedStatus) throws Exception {
        mockMvc.perform(post("/api/auth/verify-email")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + token + "\"}"))
                .andExpect(status().is(expectedStatus));
    }

    @Test
    void inscriptionEnvoieUnJetonDeVerification() throws Exception {
        String email = "verify-" + System.nanoTime() + "@test.com";
        signup(email);

        assertThat(sender.lastEmail).isEqualTo(email);
        assertThat(sender.lastToken).isNotBlank();
    }

    @Test
    void verifyAvecLeJetonValideMarqueLeCompte() throws Exception {
        String email = "verify-ok-" + System.nanoTime() + "@test.com";
        signup(email);
        String token = sender.lastToken;

        mockMvc.perform(post("/api/auth/verify-email")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + token + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Email verified successfully."));

        assertThat(verifier.emails).contains(email);

        // Usage unique : le même jeton ne repasse pas.
        verifyToken(token, 400);
        assertThat(jsonPathOfLastError("$.code")).isEqualTo("verification_token_invalid");
    }

    @Test
    void resendRenvoieUnNouveauJetonValide() throws Exception {
        String email = "resend-" + System.nanoTime() + "@test.com";
        signup(email);
        String firstToken = sender.lastToken;

        mockMvc.perform(post("/api/auth/resend-verification")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message")
                        .value("If the account exists, a verification email has been sent."));

        String secondToken = sender.lastToken;
        assertThat(secondToken).isNotBlank().isNotEqualTo(firstToken);
        verifyToken(secondToken, 200);
    }

    @Test
    void resendPourUnEmailInconnuRepondSansRevelerLexistence() throws Exception {
        mockMvc.perform(post("/api/auth/resend-verification")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"inconnu-" + System.nanoTime() + "@test.com\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message")
                        .value("If the account exists, a verification email has been sent."));

        assertThat(sender.lastEmail).isNull();
    }

    private String jsonPathOfLastError(String path) throws Exception {
        // Réutilise le dernier appel : on refait un appel invalide pour lire le code.
        var result = mockMvc.perform(post("/api/auth/verify-email")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"jeton-invalide\"}"))
                .andExpect(status().isBadRequest())
                .andReturn();
        return com.jayway.jsonpath.JsonPath.read(result.getResponse().getContentAsString(), path);
    }

    /** Expéditeur factice : capture le jeton au lieu d'envoyer un vrai e-mail. */
    @TestConfiguration(proxyBeanMethods = false)
    static class VerificationConfig {

        @Bean
        FakeVerificationSender fakeVerificationSender() {
            return new FakeVerificationSender();
        }

        @Bean
        RecordingEmailVerifier recordingEmailVerifier() {
            return new RecordingEmailVerifier();
        }
    }

    static class FakeVerificationSender implements EmailVerificationEmailSender {

        final List<String> tokens = new CopyOnWriteArrayList<>();

        volatile String lastEmail;

        volatile String lastToken;

        @Override
        public void send(String email, String rawToken) {
            this.lastEmail = email;
            this.lastToken = rawToken;
            tokens.add(rawToken);
        }
    }

    static class RecordingEmailVerifier implements AuthUserEmailVerifier {

        final List<String> emails = new CopyOnWriteArrayList<>();

        @Override
        public void verifyEmail(String email) {
            emails.add(email);
        }
    }
}
