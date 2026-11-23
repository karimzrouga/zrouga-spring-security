package zrouga.spring.security.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import zrouga.spring.security.RefreshTokenStore;
import zrouga.spring.security.StoredRefreshToken;
import zrouga.spring.security.TestSecret;

import javax.crypto.SecretKey;

import com.jayway.jsonpath.JsonPath;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest(properties = {
        "zrouga.security.reset-enabled=true",
        "zrouga.security.reset-base-url=https://front.test/reset-password"
})
@AutoConfigureMockMvc
class ZrougaSecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RefreshTokenStore refreshTokenStore;

    @Autowired
    private TestApplication.FakeEmailSender emailSender;

    private String signin(String email) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"" + TestApplication.PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        return JsonPath.read(result.getResponse().getContentAsString(), "$.token");
    }

    private Claims parse(String token) {
        SecretKey key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(TestSecret.SECRET));
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
    }

    @Test
    void signinRetourneTokens() throws Exception {
        mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + TestApplication.ADMIN_EMAIL + "\",\"password\":\""
                                + TestApplication.PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.type").value("Bearer"))
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty());
    }

    @Test
    void signinMotDePasseIncorrectRenvoie401() throws Exception {
        mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + TestApplication.ADMIN_EMAIL + "\",\"password\":\"mauvais\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Unauthorized"));
    }

    @Test
    void endpointProtegeSansJetonRenvoie401() throws Exception {
        mockMvc.perform(get("/api/hello"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.code").value("unauthorized"))
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").isNotEmpty())
                .andExpect(jsonPath("$.path").isNotEmpty())
                .andExpect(jsonPath("$.timestamp").isNotEmpty());
    }

    @Test
    void endpointProtegeAvecJetonRenvoie200() throws Exception {
        String token = signin(TestApplication.ADMIN_EMAIL);

        mockMvc.perform(get("/api/hello").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("hello"));
    }

    @Test
    void claimsJwtConformes() throws Exception {
        String token = signin(TestApplication.ADMIN_EMAIL);

        Claims claims = parse(token);
        assertThat(claims.getSubject()).isEqualTo(TestApplication.ADMIN_EMAIL);
        assertThat(((Number) claims.get("id")).longValue()).isEqualTo(1L);
        assertThat(claims.get("email")).isEqualTo(TestApplication.ADMIN_EMAIL);
        assertThat((List<Object>) claims.get("roles")).containsExactly("ADMIN", "CONTROLEUR");
        assertThat(claims.get("status")).isEqualTo(Boolean.TRUE);
        assertThat(claims.getExpiration()).isAfter(Date.from(Instant.now()));
    }

    @Test
    void utilisateurInactifNePeutPasSeConnecter() throws Exception {
        mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + TestApplication.INACTIF_EMAIL + "\",\"password\":\""
                                + TestApplication.PASSWORD + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Unauthorized"));
    }

    @Test
    void jetonValideDeCompteInactifEstRefuse() throws Exception {
        SecretKey key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(TestSecret.SECRET));
        String token = Jwts.builder()
                .setSubject(TestApplication.INACTIF_EMAIL)
                .claim("id", 2L)
                .claim("email", TestApplication.INACTIF_EMAIL)
                .claim("roles", List.of("AQP"))
                .claim("status", false)
                .setExpiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(key, Jwts.SIG.HS512)
                .compact();

        mockMvc.perform(get("/api/hello").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void headerAuthorizationMalformeRenvoie401() throws Exception {
        mockMvc.perform(get("/api/hello").header("Authorization", "Bearer abc.def.ghi"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    void refreshtokenRenvoieNouveauAccessTokenEtUnNouveauRefreshToken() throws Exception {
        MvcResult signinResult = mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + TestApplication.ADMIN_EMAIL + "\",\"password\":\""
                                + TestApplication.PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        String refreshToken = JsonPath.read(signinResult.getResponse().getContentAsString(), "$.refreshToken");

        MvcResult refreshResult = mockMvc.perform(post("/api/auth/refreshtoken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refreshToken + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andReturn();

        String rotated = JsonPath.read(refreshResult.getResponse().getContentAsString(), "$.refreshToken");
        assertThat(rotated).isNotEqualTo(refreshToken);
    }

    @Test
    void refreshtokenRefuseLaReutilisationDUnJetonTourne() throws Exception {
        MvcResult signinResult = mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + TestApplication.ADMIN_EMAIL + "\",\"password\":\""
                                + TestApplication.PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        String refreshToken = JsonPath.read(signinResult.getResponse().getContentAsString(), "$.refreshToken");

        mockMvc.perform(post("/api/auth/refreshtoken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refreshToken + "\"}"))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/auth/refreshtoken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refreshToken + "\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value("Refresh token is not in database!"));
    }

    @Test
    void refreshtokenInconnuRenvoie403SansFuiteDuJeton() throws Exception {
        mockMvc.perform(post("/api/auth/refreshtoken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"token-inexistant\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.code").value("refresh_token_rejected"))
                .andExpect(jsonPath("$.error").value("Forbidden"))
                .andExpect(jsonPath("$.message").value("Refresh token is not in database!"))
                .andExpect(jsonPath("$.timestamp").isNotEmpty());
    }

    @Test
    void refreshtokenExpireRenvoie403() throws Exception {
        StoredRefreshToken expired = refreshTokenStore.save(1L, Instant.now().minusSeconds(60));

        mockMvc.perform(post("/api/auth/refreshtoken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + expired.token() + "\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.message", containsString("expired")));
    }

    @Test
    void signoutSupprimeLeRefreshToken() throws Exception {
        MvcResult signinResult = mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + TestApplication.ADMIN_EMAIL + "\",\"password\":\""
                                + TestApplication.PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        String body = signinResult.getResponse().getContentAsString();
        String token = JsonPath.read(body, "$.token");
        String refreshToken = JsonPath.read(body, "$.refreshToken");

        mockMvc.perform(post("/api/auth/signout").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Log out successful!"));

        mockMvc.perform(post("/api/auth/refreshtoken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refreshToken + "\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message", containsString("not in database")));
    }

    @Test
    void signoutSansAuthentification() throws Exception {
        mockMvc.perform(post("/api/auth/signout"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("No logged-in user. Nothing to log out."));
    }

    @Test
    void tropDeTentativesEchoueesRenvoient429() throws Exception {
        String body = "{\"email\":\"brute-force@test.com\",\"password\":\"mauvais\"}";

        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/api/auth/signin").contentType(MediaType.APPLICATION_JSON).content(body))
                    .andExpect(status().isUnauthorized());
        }

        mockMvc.perform(post("/api/auth/signin").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.status").value(429))
                .andExpect(jsonPath("$.code").value("rate_limit_exceeded"))
                .andExpect(jsonPath("$.error").value("Too Many Requests"))
                .andExpect(jsonPath("$.message", containsString("Too many attempts")));
    }

    @Test
    void corpsDeRequeteInvalideRenvoie400Unifie() throws Exception {
        mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message", containsString("email")))
                .andExpect(jsonPath("$.path").isNotEmpty())
                .andExpect(jsonPath("$.timestamp").isNotEmpty());
    }

    @Test
    void signupCreeUnUtilisateurPuisConnexion() throws Exception {
        String email = "nouveau-" + System.nanoTime() + "@test.com";

        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"MotDePasse123\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.message").value("User registered successfully!"));

        mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"MotDePasse123\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty());
    }

    @Test
    void signupAvecEmailExistantRenvoie409() throws Exception {
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + TestApplication.ADMIN_EMAIL + "\",\"password\":\"MotDePasse123\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409))
                .andExpect(jsonPath("$.code").value("email_already_used"))
                .andExpect(jsonPath("$.error").value("Conflict"))
                .andExpect(jsonPath("$.message", containsString("already in use")));
    }

    @Test
    void signupMotDePasseTropCourtRenvoie400() throws Exception {
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"court@test.com\",\"password\":\"abc\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.code").value("validation_error"))
                .andExpect(jsonPath("$.message", containsString("password")));
    }

    @Test
    void forgotPasswordPuisResetPasswordRevoqueLesJetonAncienMotDePasse() throws Exception {
        String email = "reset-" + System.nanoTime() + "@test.com";
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"MotDePasse123\"}"))
                .andExpect(status().isCreated());

        MvcResult signinResult = mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"MotDePasse123\"}"))
                .andExpect(status().isOk())
                .andReturn();
        String oldRefreshToken = JsonPath.read(signinResult.getResponse().getContentAsString(), "$.refreshToken");

        mockMvc.perform(post("/api/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message", containsString("reset email has been sent")));

        assertThat(emailSender.lastEmail).isEqualTo(email);
        String resetToken = emailSender.lastToken;
        assertThat(resetToken).isNotBlank();

        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + resetToken + "\",\"password\":\"NouveauMotDePasse9\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Password has been reset successfully."));

        mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"MotDePasse123\"}"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"NouveauMotDePasse9\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty());

        mockMvc.perform(post("/api/auth/refreshtoken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + oldRefreshToken + "\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value("Refresh token is not in database!"));
    }

    @Test
    void forgotPasswordEmailInconnuRenvoie200SansEnvoi() throws Exception {
        emailSender.lastEmail = null;
        emailSender.lastToken = null;

        mockMvc.perform(post("/api/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"inconnu-" + System.nanoTime() + "@test.com\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message", containsString("reset email has been sent")));

        assertThat(emailSender.lastToken).isNull();
    }

    @Test
    void resetPasswordJetonInvalideRenvoie400Unifie() throws Exception {
        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"jeton-invalide\",\"password\":\"MotDePasse123\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("Invalid or expired reset token."))
                .andExpect(jsonPath("$.timestamp").isNotEmpty());
    }

    @Test
    void resetPasswordJetonReutiliseRenvoie400() throws Exception {
        String email = "reuse-" + System.nanoTime() + "@test.com";
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"MotDePasse123\"}"))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/api/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\"}"))
                .andExpect(status().isOk());

        String resetToken = emailSender.lastToken;
        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + resetToken + "\",\"password\":\"NouveauMotDePasse9\"}"))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + resetToken + "\",\"password\":\"EncoreUnAutre99\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Invalid or expired reset token."));
    }

    @Test
    void resetPasswordMotDePasseTropCourtRenvoie400() throws Exception {
        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"nimportequel\",\"password\":\"abc\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message", containsString("password")));
    }
}
