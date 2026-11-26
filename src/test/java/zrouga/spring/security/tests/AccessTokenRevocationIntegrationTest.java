package zrouga.spring.security.tests;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * {@code zrouga.security.revocation-enabled=true} : le {@code jti} de l'access
 * token présenté à la déconnexion est mis sur liste noire — le JWT devient
 * immédiatement invalide au lieu d'attendre son expiration.
 */
@SpringBootTest(properties = "zrouga.security.revocation-enabled=true")
@AutoConfigureMockMvc
class AccessTokenRevocationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    private MvcResult signin() throws Exception {
        return mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + TestApplication.ADMIN_EMAIL + "\",\"password\":\""
                                + TestApplication.PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andReturn();
    }

    private static String token(MvcResult signin) throws Exception {
        return JsonPath.read(signin.getResponse().getContentAsString(), "$.token");
    }

    private static String refreshToken(MvcResult signin) throws Exception {
        return JsonPath.read(signin.getResponse().getContentAsString(), "$.refreshToken");
    }

    @Test
    void signoutRevoqueImmediateLintAccess() throws Exception {
        String access = token(signin());

        mockMvc.perform(get("/api/hello").header("Authorization", "Bearer " + access))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/auth/signout").header("Authorization", "Bearer " + access))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Log out successful!"));

        // Le même JWT, encore non expiré, est refusé après révocation.
        mockMvc.perform(get("/api/hello").header("Authorization", "Bearer " + access))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void signoutRevoqueAussiLesRefreshTokensDuCompte() throws Exception {
        MvcResult signin = signin();
        String access = token(signin);
        String refresh = refreshToken(signin);

        mockMvc.perform(post("/api/auth/signout").header("Authorization", "Bearer " + access))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/auth/refreshtoken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refresh + "\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("refresh_token_rejected"));
    }

    @Test
    void signoutSansJetonsResteSansEffet() throws Exception {
        MvcResult signin = signin();
        String access = token(signin);

        // Sans jeton présenté, pas de révocation : le token reste valide.
        mockMvc.perform(post("/api/auth/signout"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("No logged-in user. Nothing to log out."));

        mockMvc.perform(get("/api/hello").header("Authorization", "Bearer " + access))
                .andExpect(status().isOk());
    }
}
