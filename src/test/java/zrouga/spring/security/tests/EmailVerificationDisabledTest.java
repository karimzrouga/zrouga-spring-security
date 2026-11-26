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

/** {@code email-verification-enabled=false} (défaut) : les endpoints répondent 501. */
@SpringBootTest
@AutoConfigureMockMvc
class EmailVerificationDisabledTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void verifyEmailRenvoie501() throws Exception {
        mockMvc.perform(post("/api/auth/verify-email")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"n-importe-quoi\"}"))
                .andExpect(status().isNotImplemented())
                .andExpect(jsonPath("$.code").value("verification_not_supported"));
    }

    @Test
    void resendVerificationRenvoie501() throws Exception {
        mockMvc.perform(post("/api/auth/resend-verification")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"user@test.com\"}"))
                .andExpect(status().isNotImplemented())
                .andExpect(jsonPath("$.code").value("verification_not_supported"));
    }
}
