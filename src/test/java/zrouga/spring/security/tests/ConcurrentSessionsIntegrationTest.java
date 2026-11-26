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
 * {@code zrouga.security.concurrent-sessions-enabled=true} : chaque connexion
 * crée une famille indépendante — mobile et desktop coexistent, les deux
 * refresh tokens tournent, les access tokens des deux sessions restent valides.
 */
@SpringBootTest(properties = "zrouga.security.concurrent-sessions-enabled=true")
@AutoConfigureMockMvc
class ConcurrentSessionsIntegrationTest {

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

    private void refreshOk(String refreshToken) throws Exception {
        mockMvc.perform(post("/api/auth/refreshtoken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refreshToken + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty());
    }

    private void refreshKo(String refreshToken) throws Exception {
        mockMvc.perform(post("/api/auth/refreshtoken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refreshToken + "\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("refresh_token_rejected"));
    }

    @Test
    void lesFamillesDesDeuxAppareilsCoexistent() throws Exception {
        MvcResult session1 = signin();
        String access1 = read(session1, "$.token");
        String refresh1 = read(session1, "$.refreshToken");

        MvcResult session2 = signin();
        String refresh2 = read(session2, "$.refreshToken");

        // Sans concurrent-sessions, le 2e signin aurait révoqué la famille 1.
        refreshOk(refresh1);
        refreshOk(refresh2);

        // L'access token de la session 1 reste valide après le 2e signin.
        mockMvc.perform(get("/api/hello").header("Authorization", "Bearer " + access1))
                .andExpect(status().isOk());
    }
}
