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
import org.springframework.boot.jpa.test.autoconfigure.TestEntityManager;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@DataJpaTest
@EntityScan("zrouga.spring.security.jpa")
class JpaRefreshTokenStoreTest {

    /** La couche JPA ne charge pas l'auto-config sécurité : bean minimal pour TestApplication. */
    @TestConfiguration
    static class EncoderConfiguration {

        @Bean
        PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder(4);
        }
    }

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
    void findByTokenRetourneLeJetonBrutEtLintegrite() {
        StoredRefreshToken saved = store().save(7L, Instant.now().plusSeconds(60));
        testEntityManager.flush();
        testEntityManager.clear();

        Optional<StoredRefreshToken> found = store().findByToken(saved.token());

        assertThat(found).isPresent();
        assertThat(found.get().token()).isEqualTo(saved.token());
        assertThat(found.get().userId()).isEqualTo(7L);
        assertThat(found.get().revoked()).isFalse();
        assertThat(store().findByToken("inconnu")).isEmpty();
        assertThat(store().findByToken(null)).isEmpty();
    }

    @Test
    void revokeEstAtomiqueEtNeSupprimePasLaLigne() {
        StoredRefreshToken saved = store().save(7L, Instant.now().plusSeconds(60));
        testEntityManager.flush();
        testEntityManager.clear();

        assertThat(store().revoke(saved.token())).isTrue();
        assertThat(store().revoke(saved.token())).isFalse();
        assertThat(store().revoke("inconnu")).isFalse();
        assertThat(store().revoke(null)).isFalse();

        testEntityManager.flush();
        testEntityManager.clear();

        Optional<StoredRefreshToken> found = store().findByToken(saved.token());
        assertThat(found).isPresent();
        assertThat(found.get().revoked()).isTrue();
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
