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
 * {@code zrouga.security.refresh-binding-enabled=true} : un refresh présenté
 * depuis une IP ou un User-Agent différents de ceux enregistrés à la création
 * révoque la famille entière et répond 403 (vol potentiel).
 */
@SpringBootTest(properties = {
        "zrouga.security.refresh-binding-enabled=true",
        "zrouga.security.trust-forwarded-for=true"
})
@AutoConfigureMockMvc
class RefreshBindingIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    private MvcResult signin(String userAgent) throws Exception {
        var request = post("/api/auth/signin")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"" + TestApplication.ADMIN_EMAIL + "\",\"password\":\""
                        + TestApplication.PASSWORD + "\"}");
        if (userAgent != null) {
            request = request.header("User-Agent", userAgent);
        }
        return mockMvc.perform(request)
                .andExpect(status().isOk())
                .andReturn();
    }

    private static String read(MvcResult result, String path) throws Exception {
        return JsonPath.read(result.getResponse().getContentAsString(), path);
    }

    private void refresh(String refreshToken, String userAgent, String forwardedFor, int expectedStatus)
            throws Exception {
        var request = post("/api/auth/refreshtoken")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"refreshToken\":\"" + refreshToken + "\"}");
        if (userAgent != null) {
            request = request.header("User-Agent", userAgent);
        }
        if (forwardedFor != null) {
            request = request.header("X-Forwarded-For", forwardedFor);
        }
        mockMvc.perform(request)
                .andExpect(status().is(expectedStatus));
    }

    @Test
    void refreshDepuisLaMemeOrigineReussit() throws Exception {
        MvcResult signin = signin("TestApp/1.0");
        String refresh = read(signin, "$.refreshToken");

        refresh(refresh, "TestApp/1.0", null, 200);
    }

    @Test
    void refreshDuneAutreIpRevoqueLaFamille() throws Exception {
        MvcResult signin = signin(null);
        String refresh = read(signin, "$.refreshToken");

        refresh(refresh, null, "1.2.3.4", 403);

        // La famille entière est révoquée : même l'originale devient inutilisable.
        refresh(refresh, null, null, 403);
    }

    @Test
    void refreshDunAutreUserAgentRevoqueLaFamille() throws Exception {
        MvcResult signin = signin("TestApp/1.0");
        String refresh = read(signin, "$.refreshToken");

        refresh(refresh, "AutreApp/9.9", null, 403);

        refresh(refresh, "TestApp/1.0", null, 403);
    }
}
