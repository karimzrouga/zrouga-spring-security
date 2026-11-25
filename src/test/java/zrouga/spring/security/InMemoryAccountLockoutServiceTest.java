package zrouga.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import zrouga.spring.security.exception.AccountLockedException;

import org.junit.jupiter.api.Test;

/**
 * Verrouillage de compte en mémoire : seuil, expiration, remise à zéro,
 * normalisation de l'e-mail, désactivation par défaut.
 */
class InMemoryAccountLockoutServiceTest {

    private static ZrougaSecurityProperties properties(boolean enabled, int maxAttempts, long durationMs) {
        ZrougaSecurityProperties properties = new ZrougaSecurityProperties();
        properties.setLockoutEnabled(enabled);
        properties.setLockoutMaxAttempts(maxAttempts);
        properties.setLockoutDurationMs(durationMs);
        return properties;
    }

    @Test
    void desactiveAucunEffetMemeAuDelaDuSeuil() {
        InMemoryAccountLockoutService service =
                new InMemoryAccountLockoutService(properties(false, 2, 60_000));

        for (int i = 0; i < 10; i++) {
            service.recordFailure("a@test.com");
        }

        assertThatCode(() -> service.check("a@test.com")).doesNotThrowAnyException();
    }

    @Test
    void verrouilleAuSeuilAvecCodeAccountLocked() {
        InMemoryAccountLockoutService service =
                new InMemoryAccountLockoutService(properties(true, 3, 60_000));

        service.recordFailure("a@test.com");
        service.recordFailure("a@test.com");
        assertThatCode(() -> service.check("a@test.com")).doesNotThrowAnyException();

        assertThatThrownBy(() -> service.recordFailure("a@test.com"))
                .isInstanceOf(AccountLockedException.class)
                .hasMessageContaining("locked")
                .satisfies(ex -> assertThat(((AccountLockedException) ex).code()).isEqualTo("account_locked"));

        assertThatThrownBy(() -> service.check("a@test.com"))
                .isInstanceOf(AccountLockedException.class)
                .hasMessageContaining("Try again in");
    }

    @Test
    void verrouilleUniformementUnCompteInconnu() {
        InMemoryAccountLockoutService service =
                new InMemoryAccountLockoutService(properties(true, 2, 60_000));

        service.recordFailure("jamais-vu@test.com");
        assertThatThrownBy(() -> service.recordFailure("jamais-vu@test.com"))
                .isInstanceOf(AccountLockedException.class);
    }

    @Test
    void resetRemetLeCompteurAZero() {
        InMemoryAccountLockoutService service =
                new InMemoryAccountLockoutService(properties(true, 3, 60_000));

        service.recordFailure("a@test.com");
        service.recordFailure("a@test.com");
        service.reset("a@test.com");
        service.recordFailure("a@test.com");
        service.recordFailure("a@test.com");

        assertThatCode(() -> service.check("a@test.com")).doesNotThrowAnyException();
    }

    @Test
    void casseInsensibleNormaliseLEmail() {
        InMemoryAccountLockoutService service =
                new InMemoryAccountLockoutService(properties(true, 2, 60_000));

        service.recordFailure("Jean.Test@Example.COM");
        // Même e-mail en minuscules : le 2e échec atteint le seuil → verrou.
        assertThatThrownBy(() -> service.recordFailure("jean.test@example.com"))
                .isInstanceOf(AccountLockedException.class);

        assertThatThrownBy(() -> service.check("JEAN.TEST@EXAMPLE.COM"))
                .isInstanceOf(AccountLockedException.class);
    }

    @Test
    void compteursSeparesParCompte() {
        InMemoryAccountLockoutService service =
                new InMemoryAccountLockoutService(properties(true, 2, 60_000));

        service.recordFailure("a@test.com");
        service.recordFailure("b@test.com");
        assertThatThrownBy(() -> service.recordFailure("a@test.com"))
                .isInstanceOf(AccountLockedException.class);

        assertThatThrownBy(() -> service.check("a@test.com")).isInstanceOf(AccountLockedException.class);
        assertThatCode(() -> service.check("b@test.com")).doesNotThrowAnyException();
    }

    @Test
    void verrouExpireremiseAZeroComplete() throws InterruptedException {
        InMemoryAccountLockoutService service =
                new InMemoryAccountLockoutService(properties(true, 2, 1000));

        service.recordFailure("a@test.com");
        assertThatThrownBy(() -> service.recordFailure("a@test.com"))
                .isInstanceOf(AccountLockedException.class);
        assertThatThrownBy(() -> service.check("a@test.com")).isInstanceOf(AccountLockedException.class);

        Thread.sleep(1100);

        // Verrou expiré : connexion possible et compteur reparti de zéro.
        assertThatCode(() -> service.check("a@test.com")).doesNotThrowAnyException();
        service.recordFailure("a@test.com");
        assertThatCode(() -> service.check("a@test.com")).doesNotThrowAnyException();
    }

    @Test
    void echecsPerimesNeComptentPlus() throws InterruptedException {
        InMemoryAccountLockoutService service =
                new InMemoryAccountLockoutService(properties(true, 3, 1000));

        service.recordFailure("a@test.com");
        service.recordFailure("a@test.com");
        Thread.sleep(1100);

        // Sans vieillissement, ce 3e échec verrouillerait : le compteur a été purgé.
        service.recordFailure("a@test.com");
        assertThatCode(() -> service.check("a@test.com")).doesNotThrowAnyException();
    }

    @Test
    void emailNullTraiteCommeChaineVide() {
        InMemoryAccountLockoutService service =
                new InMemoryAccountLockoutService(properties(true, 2, 60_000));

        service.recordFailure(null);
        assertThatThrownBy(() -> service.recordFailure(null)).isInstanceOf(AccountLockedException.class);

        assertThatThrownBy(() -> service.check(null)).isInstanceOf(AccountLockedException.class);
    }

    @Test
    void plafondDeComptesSuivisSansException() {
        InMemoryAccountLockoutService service =
                new InMemoryAccountLockoutService(properties(true, 100, 60_000));

        for (int i = 0; i < 10_050; i++) {
            service.recordFailure("user-" + i + "@test.com");
        }

        // État toujours cohérent après déclenchement de la purge (10 000 entrées max).
        assertThatCode(() -> service.check("user-10049@test.com")).doesNotThrowAnyException();
    }
}
