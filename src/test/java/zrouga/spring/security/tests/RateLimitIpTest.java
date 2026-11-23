package zrouga.spring.security.tests;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Limite IP par défaut (sans proxy) : toutes les requêtes viennent de
 * {@code 127.0.0.1} — au-delà de 10 × 5 tentatives sur le même e-mail, la clé IP
 * bloque avec 429. Contexte isolé (propriétés dédiées) pour ne pas polluer les
 * autres tests.
 */
@SpringBootTest(properties = {
        "zrouga.security.reset-enabled=true",
        "zrouga.security.reset-base-url=https://front.test/reset-password",
        "zrouga.security.rate-limit-window-ms=900000"
})
@AutoConfigureMockMvc
class RateLimitIpTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void bloqueeApresCinquanteRequetesDepuisLaMemeIp() throws Exception {
        for (int i = 0; i < 50; i++) {
            mockMvc.perform(post("/api/auth/forgot-password")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"email\":\"ip-" + i + "@test.com\"}"))
                    .andExpect(status().isOk());
        }

        mockMvc.perform(post("/api/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"ip-50@test.com\"}"))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.code").value("rate_limit_exceeded"))
                .andExpect(jsonPath("$.message").value("Too many attempts. Try again in a few minutes."));
    }
}
