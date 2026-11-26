package zrouga.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import zrouga.spring.security.exception.TokenRefreshException;
import zrouga.spring.security.jwt.JwtUtils;
import zrouga.spring.security.payload.TokenRefreshRequest;
import zrouga.spring.security.payload.TokenRefreshResponse;
import zrouga.spring.security.ratelimit.InMemoryLoginRateLimiter;

import org.junit.jupiter.api.Test;

/**
 * La rotation du refresh token doit rester sûre en concurrence : deux présentations
 * simultanées du même jeton ne peuvent pas toutes les deux réussir (CAS).
 */
class RefreshTokenRotationConcurrencyTest {

    /** Store qui synchronise les deux lectures : les deux threads voient le jeton non révoqué. */
    private static class BarrierRefreshTokenStore implements RefreshTokenStore {

        private final RefreshTokenStore delegate = new InMemoryRefreshTokenStore();

        private final CyclicBarrier barrier = new CyclicBarrier(2);

        @Override
        public StoredRefreshToken save(long userId, Instant expiryDate) {
            return delegate.save(userId, expiryDate);
        }

        @Override
        public Optional<StoredRefreshToken> findByToken(String token) {
            Optional<StoredRefreshToken> found = delegate.findByToken(token);
            try {
                barrier.await(5, TimeUnit.SECONDS);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
            return found;
        }

        @Override
        public boolean revoke(String token) {
            return delegate.revoke(token);
        }

        @Override
        public int deleteByUserId(long userId) {
            return delegate.deleteByUserId(userId);
        }
    }

    private record SimpleUser(Long id, String email, String password, java.util.List<String> roles,
            Boolean status) implements AuthUser {

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
        public java.util.List<String> getRoles() {
            return roles;
        }

        @Override
        public Boolean getStatus() {
            return status;
        }
    }

    private AuthService service(RefreshTokenStore store) {
        ZrougaSecurityProperties properties = new ZrougaSecurityProperties();
        properties.setJwtSecret(TestSecret.SECRET);
        AuthUser user = new SimpleUser(7L, "a@test.com", "hash", java.util.List.of("USER"), true);

        AuthUserProvider provider = new AuthUserProvider() {
            @Override
            public Optional<AuthUser> findByEmail(String email) {
                return Optional.of(user);
            }

            @Override
            public Optional<AuthUser> findById(Long id) {
                return Optional.of(user);
            }
        };

        @SuppressWarnings("unchecked")
        var providerProvider = mock(org.springframework.beans.factory.ObjectProvider.class);
        org.mockito.Mockito.when(providerProvider.getIfAvailable()).thenReturn(provider);

        return new AuthService(
                null,
                providerProvider,
                new JwtUtils(properties),
                new RefreshTokenService(store, properties),
                new InMemoryLoginRateLimiter(properties),
                null,
                mock(org.springframework.beans.factory.ObjectProvider.class),
                new InMemoryAccountLockoutService(properties),
                new PasswordPolicy(properties),
                properties,
                zrouga.spring.security.AccessTokenRevocation.disabled(),
                event -> {
                },
                new zrouga.spring.security.InMemoryTwoFactorSecretStore());
    }

    @Test
    void deuxRotationsSimultaneesNePeuventPasToutesReussir() throws Exception {
        BarrierRefreshTokenStore store = new BarrierRefreshTokenStore();
        StoredRefreshToken original = store.save(7L, Instant.now().plusSeconds(60));
        AuthService service = service(store);

        TokenRefreshRequest request = new TokenRefreshRequest();
        request.setRefreshToken(original.token());

        CountDownLatch start = new CountDownLatch(1);
        AtomicReference<TokenRefreshResponse> first = new AtomicReference<>();
        AtomicReference<Throwable> firstError = new AtomicReference<>();
        AtomicReference<TokenRefreshResponse> second = new AtomicReference<>();
        AtomicReference<Throwable> secondError = new AtomicReference<>();

        Thread t1 = new Thread(() -> runRotation(service, request, start, first, firstError));
        Thread t2 = new Thread(() -> runRotation(service, request, start, second, secondError));
        t1.start();
        t2.start();
        start.countDown();
        t1.join(10_000);
        t2.join(10_000);

        boolean firstOk = first.get() != null;
        boolean secondOk = second.get() != null;
        assertThat(firstOk ^ secondOk)
                .withFailMessage("exactement une rotation doit réussir (first=%s, firstError=%s, second=%s, secondError=%s)",
                        firstOk, firstError.get(), secondOk, secondError.get())
                .isTrue();
        assertThat(firstOk ? secondError.get() : firstError.get())
                .isInstanceOf(TokenRefreshException.class);
    }

    private void runRotation(AuthService service, TokenRefreshRequest request, CountDownLatch start,
            AtomicReference<TokenRefreshResponse> result, AtomicReference<Throwable> error) {
        try {
            start.await(5, TimeUnit.SECONDS);
            result.set(service.refreshtoken(request));
        } catch (Throwable t) {
            error.set(t);
        }
    }
}
