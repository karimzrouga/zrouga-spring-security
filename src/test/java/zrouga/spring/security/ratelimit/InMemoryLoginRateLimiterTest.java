package zrouga.spring.security.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import zrouga.spring.security.ZrougaSecurityProperties;
import zrouga.spring.security.exception.RateLimitException;

import org.junit.jupiter.api.Test;

class InMemoryLoginRateLimiterTest {

    private InMemoryLoginRateLimiter limiter(int maxAttempts, long windowMs) {
        ZrougaSecurityProperties properties = new ZrougaSecurityProperties();
        properties.setRateLimitMaxAttempts(maxAttempts);
        properties.setRateLimitWindowMs(windowMs);
        return new InMemoryLoginRateLimiter(properties);
    }

    @Test
    void bloqueAuSeuilAvecMessageAnglais() {
        InMemoryLoginRateLimiter limiter = limiter(5, 900_000L);

        for (int i = 0; i < 5; i++) {
            assertThatCode(() -> limiter.check("signin:email:a@test.com")).doesNotThrowAnyException();
        }

        assertThatThrownBy(() -> limiter.check("signin:email:a@test.com"))
                .isInstanceOf(RateLimitException.class)
                .hasMessage("Too many attempts. Try again in a few minutes.");
    }

    @Test
    void resetReinitialiseLeCompteur() {
        InMemoryLoginRateLimiter limiter = limiter(2, 900_000L);

        limiter.check("k");
        limiter.check("k");
        assertThatThrownBy(() -> limiter.check("k")).isInstanceOf(RateLimitException.class);

        limiter.reset("k");
        assertThatCode(() -> limiter.check("k")).doesNotThrowAnyException();
    }

    @Test
    void seuilIpDixFoisPlusEleve() {
        InMemoryLoginRateLimiter limiter = limiter(5, 900_000L);

        for (int i = 0; i < 50; i++) {
            assertThatCode(() -> limiter.checkIp("signin:ip:1.2.3.4")).doesNotThrowAnyException();
        }

        assertThatThrownBy(() -> limiter.checkIp("signin:ip:1.2.3.4"))
                .isInstanceOf(RateLimitException.class);
    }

    @Test
    void clesEmailEtIpIndependantes() {
        InMemoryLoginRateLimiter limiter = limiter(2, 900_000L);

        limiter.check("signin:email:a@test.com");
        limiter.check("signin:email:a@test.com");
        assertThatThrownBy(() -> limiter.check("signin:email:a@test.com"))
                .isInstanceOf(RateLimitException.class);

        assertThatCode(() -> limiter.check("signin:email:b@test.com")).doesNotThrowAnyException();
        assertThatCode(() -> limiter.checkIp("signin:ip:9.9.9.9")).doesNotThrowAnyException();
    }

    @Test
    void fenetreExpireeDebloque() throws Exception {
        InMemoryLoginRateLimiter limiter = limiter(2, 1000L);

        limiter.check("k");
        limiter.check("k");
        assertThatThrownBy(() -> limiter.check("k")).isInstanceOf(RateLimitException.class);

        Thread.sleep(1100);

        assertThatCode(() -> limiter.check("k")).doesNotThrowAnyException();
    }

    @Test
    void evictionDesClesExpiresesQuandLeSeuilAtteint() {
        InMemoryLoginRateLimiter limiter = limiter(5, 900_000L);

        for (int i = 0; i < 10_050; i++) {
            limiter.check("clen" + i);
            limiter.checkIp("cleip" + i);
        }

        assertThatCode(() -> limiter.check("encore-une")).doesNotThrowAnyException();
    }
}
