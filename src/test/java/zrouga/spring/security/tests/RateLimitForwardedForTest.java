package zrouga.spring.security.tests;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/**
 * {@code zrouga.security.trust-forwarded-for=true} : l'IP réelle est lue dans
 * {@code X-Forwarded-For} — 55 requêtes avec 55 IP distinctes passent toutes,
 * alors que le même scénario sans proxy serait bloqué à 50 sur {@code 127.0.0.1}
 * (cf. {@link RateLimitIpTest}).
 */
@SpringBootTest(properties = {
        "zrouga.security.reset-enabled=true",
        "zrouga.security.reset-base-url=https://front.test/reset-password",
        "zrouga.security.trust-forwarded-for=true"
})
@AutoConfigureMockMvc
class RateLimitForwardedForTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void ipsDifferentesDansXForwardedForNeSeCumulentPas() throws Exception {
        for (int i = 0; i < 55; i++) {
            mockMvc.perform(post("/api/auth/forgot-password")
                            .contentType(MediaType.APPLICATION_JSON)
                            .header("X-Forwarded-For", "10.0." + (i / 250) + "." + (i % 250 + 1))
                            .content("{\"email\":\"fwd-" + i + "@test.com\"}"))
                    .andExpect(status().isOk());
        }
    }
}
