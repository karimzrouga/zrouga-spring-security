package zrouga.spring.security.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import zrouga.spring.security.ZrougaSecurityMetrics;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import io.micrometer.core.instrument.MeterRegistry;

/**
 * {@code spring-boot-starter-actuator} sur le classpath : les événements
 * d'auth alimentent les compteurs Micrometer du starter.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SecurityMetricsIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private MeterRegistry registry;

    private double count(String name, String... tags) {
        var counter = registry.find(name).tags(tags).counter();
        return counter == null ? 0 : counter.count();
    }

    private void signin(String email, String password) throws Exception {
        mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk());
    }

    @Test
    void signinReussiIncrmenteLeCompteurSuccess() throws Exception {
        double before = count(ZrougaSecurityMetrics.SIGNIN, "outcome", "success");

        signin(TestApplication.ADMIN_EMAIL, TestApplication.PASSWORD);

        assertThat(count(ZrougaSecurityMetrics.SIGNIN, "outcome", "success")).isEqualTo(before + 1);
    }

    @Test
    void signinEchoueIncrmenteLeCompteurFailure() throws Exception {
        double before = count(ZrougaSecurityMetrics.SIGNIN, "outcome", "failure");

        mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + TestApplication.ADMIN_EMAIL + "\",\"password\":\"mauvais\"}"))
                .andExpect(status().isUnauthorized());

        assertThat(count(ZrougaSecurityMetrics.SIGNIN, "outcome", "failure")).isEqualTo(before + 1);
    }

    @Test
    void signinReussiNeTouchePasAuCompteurFailure() throws Exception {
        double before = count(ZrougaSecurityMetrics.SIGNIN, "outcome", "failure");

        signin(TestApplication.ADMIN_EMAIL, TestApplication.PASSWORD);

        assertThat(count(ZrougaSecurityMetrics.SIGNIN, "outcome", "failure")).isEqualTo(before);
    }
}
