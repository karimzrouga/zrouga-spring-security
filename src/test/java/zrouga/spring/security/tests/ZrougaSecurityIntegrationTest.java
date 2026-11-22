package zrouga.spring.security.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.List;

import zrouga.spring.security.RefreshTokenStore;
import zrouga.spring.security.StoredRefreshToken;

import com.jayway.jsonpath.JsonPath;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest
@AutoConfigureMockMvc
class ZrougaSecurityIntegrationTest {

    private static final String SECRET =
            "ZROUGATESTSECRET0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RefreshTokenStore refreshTokenStore;

    private String signin(String email) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"" + TestApplication.PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        return JsonPath.read(result.getResponse().getContentAsString(), "$.token");
    }

    private Claims parse(String token) {
        return Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody();
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
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").isNotEmpty());
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
        assertThat(claims.getExpiration()).isAfter(java.util.Date.from(Instant.now()));
    }

    @Test
    void utilisateurInactifPeutSeConnecterAvecStatusFalse() throws Exception {
        String token = signin(TestApplication.INACTIF_EMAIL);

        Claims claims = parse(token);
        assertThat((List<Object>) claims.get("roles")).containsExactly("AQP");
        assertThat(claims.get("status")).isEqualTo(Boolean.FALSE);
    }

    @Test
    void refreshtokenRenvoieNouveauAccessToken() throws Exception {
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
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").value(refreshToken))
                .andExpect(jsonPath("$.tokenType").value("Bearer"));
    }

    @Test
    void refreshtokenInconnuRenvoie403() throws Exception {
        mockMvc.perform(post("/api/auth/refreshtoken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"token-inexistant\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.statusCode").value(403))
                .andExpect(jsonPath("$.message", containsString("Failed for")));
    }

    @Test
    void refreshtokenExpireRenvoie403() throws Exception {
        StoredRefreshToken expired = refreshTokenStore.save(1L, Instant.now().minusSeconds(60));

        mockMvc.perform(post("/api/auth/refreshtoken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + expired.token() + "\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.statusCode").value(403))
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
}
