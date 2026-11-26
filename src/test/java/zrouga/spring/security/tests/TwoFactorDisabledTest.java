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

/** {@code two-factor-enabled=false} (défaut) : les endpoints 2FA répondent 501. */
@SpringBootTest
@AutoConfigureMockMvc
class TwoFactorDisabledTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void setupRenvoie501() throws Exception {
        mockMvc.perform(post("/api/auth/2fa/setup"))
                .andExpect(status().isNotImplemented())
                .andExpect(jsonPath("$.code").value("two_factor_not_supported"));
    }

    @Test
    void verifyRenvoie501() throws Exception {
        mockMvc.perform(post("/api/auth/2fa/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"twoFactorToken\":\"x\",\"code\":\"123456\"}"))
                .andExpect(status().isNotImplemented())
                .andExpect(jsonPath("$.code").value("two_factor_not_supported"));
    }
}
