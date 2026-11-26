package zrouga.spring.security.tests;

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
 * Comportement par défaut (mono-session) : un {@code /signin} révoque les
 * familles de refresh tokens précédentes du même utilisateur — seul le dernier
 * appareil connecté peut rafraîchir.
 */
@SpringBootTest
@AutoConfigureMockMvc
class MonoSessionSignInTest {

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

    @Test
    void leSecondSigninRevoqueLaFamillePrecedente() throws Exception {
        MvcResult session1 = signin();
        String refresh1 = read(session1, "$.refreshToken");

        MvcResult session2 = signin();
        String refresh2 = read(session2, "$.refreshToken");

        // L'appareil 1 a été déconnecté par le signin de l'appareil 2.
        mockMvc.perform(post("/api/auth/refreshtoken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refresh1 + "\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("refresh_token_rejected"));

        // Seul le dernier appareil conserve une famille valide.
        mockMvc.perform(post("/api/auth/refreshtoken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refresh2 + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty());
    }
}
