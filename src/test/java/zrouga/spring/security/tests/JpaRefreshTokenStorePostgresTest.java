package zrouga.spring.security.tests;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import zrouga.spring.security.StoredRefreshToken;
import zrouga.spring.security.TokenHashing;
import zrouga.spring.security.jpa.JpaRefreshTokenStore;

import jakarta.persistence.EntityManager;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.jpa.test.autoconfigure.TestEntityManager;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import org.springframework.boot.testcontainers.service.connection.ServiceConnection;

/**
 * Le store JPA contre un <b>postgreSQL réel</b> (Testcontainers) plutôt que
 * H2 : valide le dialecte, le hash SHA-256, le binding IP/UA et la rotation
 * sur la base cible.
 *
 * <p>Skip automatique sans Docker ({@code disabledWithoutDocker}) — le test
 * tourne en CI (ubuntu-latest) et sur les postes avec Docker.</p>
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@EntityScan("zrouga.spring.security.jpa")
class JpaRefreshTokenStorePostgresTest {

    /** La couche JPA ne charge pas l'auto-config sécurité : bean minimal pour TestApplication. */
    @TestConfiguration
    static class EncoderConfiguration {

        @Bean
        PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder(4);
        }
    }

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:16-alpine");

    @Autowired
    private EntityManager entityManager;

    @Autowired
    private TestEntityManager testEntityManager;

    private JpaRefreshTokenStore store() {
        return new JpaRefreshTokenStore(entityManager);
    }

    private Optional<String> persistedTokenOf(String raw) {
        List<String> results = entityManager
                .createQuery("SELECT r.token FROM refreshtoken r WHERE r.token = :token", String.class)
                .setParameter("token", TokenHashing.sha256Hex(raw))
                .getResultList();
        return results.stream().findFirst();
    }

    @Test
    void saveNePersisteQueLEmpreinteSha256() {
        StoredRefreshToken saved = store().save(7L, Instant.now().plusSeconds(60));
        testEntityManager.flush();
        testEntityManager.clear();

        assertThat(saved.token()).isNotBlank();
        assertThat(persistedTokenOf(saved.token())).isPresent();
        assertThat(persistedTokenOf(saved.token()).get()).isNotEqualTo(saved.token())
                .isEqualTo(TokenHashing.sha256Hex(saved.token()));
    }

    @Test
    void bindingIpEtUserAgentSurvitAuRoundtrip() {
        StoredRefreshToken saved = store().save(9L, Instant.now().plusSeconds(60), "10.0.0.7", "App/1.0");
        testEntityManager.flush();
        testEntityManager.clear();

        Optional<StoredRefreshToken> found = store().findByToken(saved.token());

        assertThat(found).isPresent();
        assertThat(found.get().ip()).isEqualTo("10.0.0.7");
        assertThat(found.get().userAgent()).isEqualTo("App/1.0");
        assertThat(found.get().revoked()).isFalse();
    }

    @Test
    void revokeEstAtomiqueEtPreserveLeBinding() {
        StoredRefreshToken saved = store().save(7L, Instant.now().plusSeconds(60), "10.0.0.7", "App/1.0");
        testEntityManager.flush();
        testEntityManager.clear();

        assertThat(store().revoke(saved.token())).isTrue();
        assertThat(store().revoke(saved.token())).isFalse();

        testEntityManager.flush();
        testEntityManager.clear();

        Optional<StoredRefreshToken> found = store().findByToken(saved.token());
        assertThat(found).isPresent();
        assertThat(found.get().revoked()).isTrue();
        assertThat(found.get().ip()).isEqualTo("10.0.0.7");
        assertThat(found.get().userAgent()).isEqualTo("App/1.0");
    }

    @Test
    void deleteByUserIdNeToucheQueLesTokensDeLUtilisateur() {
        StoredRefreshToken deSept = store().save(7L, Instant.now().plusSeconds(60));
        StoredRefreshToken deHuit = store().save(8L, Instant.now().plusSeconds(60));
        testEntityManager.flush();
        testEntityManager.clear();

        assertThat(store().deleteByUserId(7L)).isEqualTo(1);
        assertThat(store().findByToken(deSept.token())).isEmpty();
        assertThat(store().findByToken(deHuit.token())).isPresent();
    }

    @Test
    void deleteExpiredNeToucheQueLesTokensExpires() {
        StoredRefreshToken expire = store().save(7L, Instant.now().minusSeconds(10));
        StoredRefreshToken valide = store().save(7L, Instant.now().plusSeconds(60));
        testEntityManager.flush();
        testEntityManager.clear();

        assertThat(store().deleteExpired(Instant.now())).isEqualTo(1);
        assertThat(store().findByToken(expire.token())).isEmpty();
        assertThat(store().findByToken(valide.token())).isPresent();
    }
}
