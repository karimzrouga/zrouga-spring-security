package zrouga.spring.security.tests;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import zrouga.spring.security.AuthUser;
import zrouga.spring.security.AuthUserProvider;
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

    @Bean
    public AuthUserProvider authUserProvider(PasswordEncoder passwordEncoder) {
        Map<Long, AuthUser> byId = new HashMap<>();
        Map<String, AuthUser> byEmail = new HashMap<>();
        register(byId, byEmail, new TestUser(1L, ADMIN_EMAIL, passwordEncoder.encode(PASSWORD),
                List.of("ADMIN", "CONTROLEUR"), true));
        register(byId, byEmail, new TestUser(2L, INACTIF_EMAIL, passwordEncoder.encode(PASSWORD),
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

    private static void register(Map<Long, AuthUser> byId, Map<String, AuthUser> byEmail, TestUser user) {
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
