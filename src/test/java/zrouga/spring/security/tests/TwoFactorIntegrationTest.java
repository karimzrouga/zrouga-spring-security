package zrouga.spring.security.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;

import zrouga.spring.security.totp.Totp;

import com.jayway.jsonpath.JsonPath;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * {@code zrouga.security.two-factor-enabled=true} : setup → enable → signin
 * répond un challenge au lieu des tokens → verify échange code + challenge
 * contre les tokens normaux → disable restaure le signin simple.
 */
@SpringBootTest(properties = "zrouga.security.two-factor-enabled=true")
@AutoConfigureMockMvc
class TwoFactorIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    private MvcResult signin() throws Exception {
        return mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + TestApplication.ADMIN_EMAIL + "\",\"password\":\""
                                + TestApplication.PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
    }

    private static String read(MvcResult result, String path) throws Exception {
        return JsonPath.read(result.getResponse().getContentAsString(), path);
    }

    private static String currentCode(String secret) {
        long counter = Instant.now().getEpochSecond() / 30;
        return Totp.codeAt(secret, counter);
    }

    private static String wrongCode(String code) {
        return String.format("%06d", (Integer.parseInt(code) + 500_000) % 1_000_000);
    }

    private String setupAndGetSecret() throws Exception {
        MvcResult signin = signin();
        String access = read(signin, "$.token");

        MvcResult setup = mockMvc.perform(post("/api/auth/2fa/setup")
                        .header("Authorization", "Bearer " + access))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.secret").isNotEmpty())
                .andExpect(jsonPath("$.otpauthUri").value(
                        org.hamcrest.Matchers.containsString("otpauth://totp/")))
                .andReturn();
        return read(setup, "$.secret");
    }

    private void enable(String access, String code) throws Exception {
        mockMvc.perform(post("/api/auth/2fa/enable")
                        .header("Authorization", "Bearer " + access)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"" + code + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Two-factor authentication enabled."));
    }

    @Test
    void setupSansAuthentificationRenvoie401() throws Exception {
        mockMvc.perform(post("/api/auth/2fa/setup"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("authentication_required"));
    }

    @Test
    void fluxCompletSetupEnableSigninVerifyDisable() throws Exception {
        // Setup + enable
        String secret = setupAndGetSecret();
        MvcResult signin1 = signin();
        String access = read(signin1, "$.token");
        enable(access, currentCode(secret));

        // Signin suivant : challenge au lieu des tokens
        MvcResult challenge = signin();
        String challengeToken = read(challenge, "$.twoFactorToken");
        assertThatTwoFactorRequired(challenge);
        assertThatNoTokens(challenge);

        // Mauvais code → 400, bon code → tokens
        mockMvc.perform(post("/api/auth/2fa/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"twoFactorToken\":\"" + challengeToken + "\",\"code\":\""
                                + wrongCode(currentCode(secret)) + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("invalid_two_factor_code"));

        MvcResult verified = mockMvc.perform(post("/api/auth/2fa/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"twoFactorToken\":\"" + challengeToken + "\",\"code\":\""
                                + currentCode(secret) + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andReturn();

        String access2 = read(verified, "$.token");
        mockMvc.perform(get("/api/hello").header("Authorization", "Bearer " + access2))
                .andExpect(status().isOk());

        // Disable puis signin nominal rétabli
        mockMvc.perform(post("/api/auth/2fa/disable")
                        .header("Authorization", "Bearer " + access2)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"" + currentCode(secret) + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Two-factor authentication disabled."));

        MvcResult afterDisable = signin();
        assertThatNoChallenge(afterDisable);
        assertThat(afterDisable.getResponse().getContentAsString()).contains("\"token\"");
    }

    @Test
    void challengeInvalideOuEchangeRenvoie401() throws Exception {
        mockMvc.perform(post("/api/auth/2fa/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"twoFactorToken\":\"jeton-non-signe\",\"code\":\"123456\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("two_factor_token_invalid"));
    }

    @Test
    void enableSansSetupPrealableRenvoie400() throws Exception {
        MvcResult signin = signin();
        String access = read(signin, "$.token");

        mockMvc.perform(post("/api/auth/2fa/enable")
                        .header("Authorization", "Bearer " + access)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"123456\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("invalid_two_factor_code"));
    }

    private void assertThatTwoFactorRequired(MvcResult result) throws Exception {
        Object required = JsonPath.read(result.getResponse().getContentAsString(), "$.twoFactorRequired");
        assertThat(required).isEqualTo(true);
    }

    private void assertThatNoTokens(MvcResult result) throws Exception {
        String body = result.getResponse().getContentAsString();
        assertThat(body).doesNotContain("\"token\":").doesNotContain("\"refreshToken\":");
    }

    private void assertThatNoChallenge(MvcResult result) throws Exception {
        assertThat(result.getResponse().getContentAsString()).doesNotContain("twoFactorRequired");
    }
}
