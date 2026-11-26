package zrouga.spring.security.tests;

import static org.assertj.core.api.Assertions.assertThat;

import zrouga.spring.security.ZrougaSecurityHealthIndicator;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;

/**
 * Indicateur de santé : composant {@code zrougaSecurity} toujours UP, détails =
 * fonctionnalités optionnelles lues dans la configuration.
 */
@SpringBootTest
class SecurityHealthIndicatorTest {

    @Autowired
    private ZrougaSecurityHealthIndicator indicator;

    @Test
    void healthUpEtExposeLaConfiguration() {
        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.UP);
        assertThat(health.getDetails())
                .containsEntry("authMode", "header")
                .containsEntry("revocation", false)
                .containsEntry("concurrentSessions", false)
                .containsEntry("refreshBinding", false)
                .containsEntry("emailVerification", false)
                .containsEntry("twoFactor", false)
                .containsEntry("lockout", false)
                .containsEntry("passwordPolicy", false)
                .containsEntry("passwordReset", false);
    }
}
