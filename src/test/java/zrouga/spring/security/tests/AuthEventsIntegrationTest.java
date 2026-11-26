package zrouga.spring.security.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import zrouga.spring.security.event.LockoutEvent;
import zrouga.spring.security.event.PasswordResetEvent;
import zrouga.spring.security.event.SignInEvent;
import zrouga.spring.security.event.SignOutEvent;
import zrouga.spring.security.event.SignUpEvent;
import zrouga.spring.security.event.TokenRefreshedEvent;

import com.jayway.jsonpath.JsonPath;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.event.EventListener;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Événements d'audit publiés par le starter ({@code ApplicationEventPublisher}) :
 * inscrivez vos propres listeners pour journaliser, alerter ou exporter.
 */
@SpringBootTest(properties = {
        "zrouga.security.lockout-enabled=true",
        "zrouga.security.lockout-max-attempts=2",
        "zrouga.security.reset-enabled=true",
        "zrouga.security.reset-base-url=https://front.test/reset-password"
})
@AutoConfigureMockMvc
class AuthEventsIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private EventCollector collector;

    @Autowired
    private TestApplication.FakeEmailSender emailSender;

    @BeforeEach
    void reset() {
        collector.events.clear();
        emailSender.lastEmail = null;
        emailSender.lastToken = null;
    }

    @Test
    void signinPublieSignInEvent() throws Exception {
        mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + TestApplication.ADMIN_EMAIL + "\",\"password\":\""
                                + TestApplication.PASSWORD + "\"}"))
                .andExpect(status().isOk());

        assertThat(collector.events).anyMatch(event -> event instanceof SignInEvent signIn
                && signIn.email().equals(TestApplication.ADMIN_EMAIL)
                && signIn.userId() == 1L
                && signIn.ip().equals("127.0.0.1"));
    }

    @Test
    void refreshPublieTokenRefreshedEvent() throws Exception {
        MvcResult signin = mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + TestApplication.ADMIN_EMAIL + "\",\"password\":\""
                                + TestApplication.PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        String refresh = JsonPath.read(signin.getResponse().getContentAsString(), "$.refreshToken");
        collector.events.clear();

        mockMvc.perform(post("/api/auth/refreshtoken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refresh + "\"}"))
                .andExpect(status().isOk());

        assertThat(collector.events)
                .anyMatch(event -> event instanceof TokenRefreshedEvent refreshed && refreshed.userId() == 1L);
    }

    @Test
    void signoutPublieSignOutEvent() throws Exception {
        MvcResult signin = mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + TestApplication.ADMIN_EMAIL + "\",\"password\":\""
                                + TestApplication.PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        String access = JsonPath.read(signin.getResponse().getContentAsString(), "$.token");
        collector.events.clear();

        mockMvc.perform(post("/api/auth/signout").header("Authorization", "Bearer " + access))
                .andExpect(status().isOk());

        assertThat(collector.events)
                .anyMatch(event -> event instanceof SignOutEvent signOut && signOut.userId() == 1L);
    }

    @Test
    void signupPublieSignUpEvent() throws Exception {
        String email = "events-" + System.nanoTime() + "@test.com";

        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"MotDePasse@123\"}"))
                .andExpect(status().isCreated());

        assertThat(collector.events).anyMatch(event -> event instanceof SignUpEvent signUp
                && signUp.email().equals(email)
                && signUp.ip().equals("127.0.0.1"));
    }

    @Test
    void verrouillagePublieLockoutEvent() throws Exception {
        String email = "ghost-" + System.nanoTime() + "@test.com";

        mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"mauvais-1\"}"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"mauvais-2\"}"))
                .andExpect(status().isLocked());

        assertThat(collector.events).anyMatch(event -> event instanceof LockoutEvent lockout
                && lockout.email().equals(email)
                && lockout.ip().equals("127.0.0.1"));
    }

    @Test
    void resetPasswordPubliePasswordResetEvent() throws Exception {
        String email = "reset-" + System.nanoTime() + "@test.com";
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"MotDePasse@123\"}"))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/api/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\"}"))
                .andExpect(status().isOk());
        assertThat(emailSender.lastToken).isNotBlank();
        collector.events.clear();

        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + emailSender.lastToken + "\",\"password\":\"NouveauMotDePasse123\"}"))
                .andExpect(status().isOk());

        assertThat(collector.events).anyMatch(event -> event instanceof PasswordResetEvent reset
                && reset.email().equals(email));
    }

    /** Capture tous les événements publiés dans le contexte de test. */
    @TestConfiguration(proxyBeanMethods = false)
    static class EventCollector {

        final List<Object> events = Collections.synchronizedList(new ArrayList<>());

        @EventListener
        void on(Object event) {
            events.add(event);
        }
    }
}
