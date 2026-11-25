package zrouga.demo;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import zrouga.spring.security.AuthUser;
import zrouga.spring.security.AuthUserCreator;
import zrouga.spring.security.AuthUserPasswordUpdater;
import zrouga.spring.security.AuthUserProvider;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Comptes en mémoire du démonstrateur : les trois ponts SPI du starter
 * (lookup, inscription, réinitialisation) sur un magasin {@code ConcurrentHashMap}.
 */
@Component
public class DemoAccounts implements AuthUserProvider, AuthUserCreator, AuthUserPasswordUpdater {

    private final Map<String, AuthUser> accounts = new ConcurrentHashMap<>();
    private final AtomicLong sequence = new AtomicLong(1);

    public DemoAccounts(PasswordEncoder passwordEncoder) {
        create("demo@demo.com", passwordEncoder.encode("Demo1234!"));
    }

    @Override
    public Optional<AuthUser> findByEmail(String email) {
        return Optional.ofNullable(accounts.get(email));
    }

    @Override
    public Optional<AuthUser> findById(Long id) {
        return accounts.values().stream().filter(user -> user.getId().equals(id)).findFirst();
    }

    @Override
    public void create(String email, String encodedPassword) {
        accounts.put(email, new InMemoryUser(sequence.getAndIncrement(), email, encodedPassword));
    }

    @Override
    public void updatePassword(String email, String encodedPassword) {
        accounts.computeIfPresent(email, (key, user) -> new InMemoryUser(
                user.getId(), user.getEmail(), encodedPassword));
    }

    private record InMemoryUser(Long id, String email, String password) implements AuthUser {

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
            return List.of("USER");
        }

        @Override
        public Boolean getStatus() {
            return true;
        }
    }
}
