package zrouga.spring.security.tests;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import zrouga.spring.security.AuthUser;
import zrouga.spring.security.AuthUserCreator;
import zrouga.spring.security.AuthUserPasswordUpdater;
import zrouga.spring.security.AuthUserProvider;
import zrouga.spring.security.PasswordResetEmailSender;
import zrouga.spring.security.payload.MessageResponse;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class TestApplication {

    public static final String ADMIN_EMAIL = "admin@test.com";

    public static final String INACTIF_EMAIL = "inactif@test.com";

    public static final String PASSWORD = "Admin@1234";

    private final Map<Long, AuthUser> byId = new HashMap<>();

    private final Map<String, AuthUser> byEmail = new HashMap<>();

    private final AtomicLong nextId = new AtomicLong(3L);

    @Bean
    public AuthUserProvider authUserProvider(PasswordEncoder passwordEncoder) {
        register(new TestUser(1L, ADMIN_EMAIL, passwordEncoder.encode(PASSWORD),
                List.of("ADMIN", "CONTROLEUR"), true));
        register(new TestUser(2L, INACTIF_EMAIL, passwordEncoder.encode(PASSWORD),
                List.of("AQP"), false));

        return new AuthUserProvider() {
            @Override
            public Optional<AuthUser> findByEmail(String email) {
                return Optional.ofNullable(byEmail.get(email));
            }

            @Override
            public Optional<AuthUser> findById(Long id) {
                return Optional.ofNullable(byId.get(id));
            }
        };
    }

    @Bean
    public AuthUserCreator authUserCreator() {
        return (email, encodedPassword) -> {
            long id = nextId.getAndIncrement();
            register(new TestUser(id, email, encodedPassword, List.of("USER"), true));
        };
    }

    @Bean
    public AuthUserPasswordUpdater authUserPasswordUpdater() {
        return (email, encodedPassword) -> {
            AuthUser existing = byEmail.get(email);
            if (existing != null) {
                TestUser updated = new TestUser(existing.getId(), email, encodedPassword,
                        existing.getRoles(), existing.getStatus());
                byId.put(updated.getId(), updated);
                byEmail.put(email, updated);
            }
        };
    }

    @Bean
    public FakeEmailSender fakeEmailSender() {
        return new FakeEmailSender();
    }

    /** Capte l'e-mail de réinitialisation au lieu d'envoyer un vrai SMTP en test. */
    public static class FakeEmailSender implements PasswordResetEmailSender {

        public volatile String lastEmail;

        public volatile String lastToken;

        @Override
        public void send(String email, String rawToken) {
            this.lastEmail = email;
            this.lastToken = rawToken;
        }
    }

    private void register(TestUser user) {
        byId.put(user.getId(), user);
        byEmail.put(user.getEmail(), user);
    }

    record TestUser(Long id, String email, String password, List<String> roles, Boolean status) implements AuthUser {

        @Override
        public Long getId() {
            return id;
        }

        @Override
        public String getEmail() {
            return email;
        }

        @Override
        public String getPassword() {
            return password;
        }

        @Override
        public List<String> getRoles() {
            return roles;
        }

        @Override
        public Boolean getStatus() {
            return status;
        }
    }

    @RestController
    static class ProtectedResource {

        @GetMapping("/api/hello")
        public ResponseEntity<MessageResponse> hello() {
            return ResponseEntity.ok(new MessageResponse("hello"));
        }
    }
}
