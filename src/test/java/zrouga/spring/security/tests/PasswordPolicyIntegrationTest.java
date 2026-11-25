package zrouga.spring.security.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Politique de mot de passe activée (complexe + historique de 2) : refus
 * {@code 400 weak_password} sur /signup et /reset-password, jeton de
 * réinitialisation préservé après un refus, anti-réutilisation du mot de
 * passe courant et des précédents.
 */
@SpringBootTest(properties = {
        "zrouga.security.password-policy-enabled=true",
        "zrouga.security.password-history-count=2",
        "zrouga.security.reset-enabled=true",
        "zrouga.security.reset-base-url=https://front.test/reset-password"
})
@AutoConfigureMockMvc
class PasswordPolicyIntegrationTest {

    private static final String STRONG = "MotDePasse@123";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TestApplication.FakeEmailSender emailSender;

    private void signup(String email, String password, int expectedStatus) throws Exception {
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().is(expectedStatus));
    }

    private void signin(String email, String password, int expectedStatus) throws Exception {
        mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().is(expectedStatus));
    }

    private String forgotPassword(String email) throws Exception {
        mockMvc.perform(post("/api/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\"}"))
                .andExpect(status().isOk());
        assertThat(emailSender.lastEmail).isEqualTo(email);
        return emailSender.lastToken;
    }

    private void resetPassword(String token, String password, int expectedStatus) throws Exception {
        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + token + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().is(expectedStatus));
    }

    @Test
    void signupMotDePasseFaibleRenvoie400WeakPassword() throws Exception {
        String email = "policy-" + System.nanoTime() + "@test.com";

        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"abcdefghij\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("weak_password"))
                .andExpect(jsonPath("$.message").value(
                        "Password must contain an uppercase letter, a digit, a special character."));

        // Le refus n'a pas créé de compte : le même e-mail avec un mot de passe fort passe.
        signup(email, STRONG, 201);
        signin(email, STRONG, 200);
    }

    @Test
    void resetMotDePasseFaibleNeConsommePasLeJeton() throws Exception {
        String email = "reset-weak-" + System.nanoTime() + "@test.com";
        signup(email, STRONG, 201);

        String token = forgotPassword(email);
        resetPassword(token, "abcdefghij", 400);

        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + token + "\",\"password\":\"abcdefghij\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("weak_password"));

        // Le jeton n'a pas été consommé : tentative valide acceptée.
        resetPassword(token, "NouveauMot@456", 200);
        signin(email, STRONG, 401);
        signin(email, "NouveauMot@456", 200);
    }

    @Test
    void resetRefuseLeMotDePasseCourant() throws Exception {
        String email = "reset-current-" + System.nanoTime() + "@test.com";
        signup(email, STRONG, 201);

        String token = forgotPassword(email);
        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + token + "\",\"password\":\"" + STRONG + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("weak_password"))
                .andExpect(jsonPath("$.message")
                        .value("Password was recently used: choose a password you have not used before."));
    }

    @Test
    void resetRefuseLesMotsDePasseDeLHistorique() throws Exception {
        String email = "reset-history-" + System.nanoTime() + "@test.com";
        String premier = "Premier@1234";
        String deuxieme = "Deuxieme@1234";
        String troisieme = "Troisieme@1234";
        String quatrieme = "Quatrieme@1234";

        signup(email, premier, 201);

        // 1re réinitialisation : l'ancien (premier) rejoint l'historique.
        resetPassword(forgotPassword(email), deuxieme, 200);
        // 2e : (premier, deuxieme) dans l'historique — taille max 2.
        resetPassword(forgotPassword(email), troisieme, 200);

        // Refus des deux entrées de l'historique.
        MvcResult refus1 = mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + forgotPassword(email) + "\",\"password\":\""
                                + premier + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("weak_password"))
                .andReturn();
        assertThat(refus1.getResponse().getContentAsString()).contains("recently used");

        resetPassword(forgotPassword(email), deuxieme, 400);

        // Mot de passe neuf : accepté, l'historique glisse.
        resetPassword(forgotPassword(email), quatrieme, 200);

        signin(email, quatrieme, 200);
        signin(email, troisieme, 401);
    }
}
