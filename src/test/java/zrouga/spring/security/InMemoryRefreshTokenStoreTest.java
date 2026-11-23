package zrouga.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;

import org.junit.jupiter.api.Test;

class InMemoryRefreshTokenStoreTest {

    private final InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();

    @Test
    void saveEtFindByToken() {
        StoredRefreshToken saved = store.save(7L, Instant.now().plusSeconds(60));

        assertThat(saved.token()).isNotBlank();
        assertThat(store.findByToken(saved.token())).contains(saved);
    }

    @Test
    void findByTokenInconnuVide() {
        assertThat(store.findByToken("inconnu")).isEmpty();
    }

    @Test
    void revokeEstAtomiqueEtDetecteLaReutilisation() {
        StoredRefreshToken saved = store.save(7L, Instant.now().plusSeconds(60));

        assertThat(store.revoke(saved.token())).isTrue();
        assertThat(store.findByToken(saved.token())).contains(
                new StoredRefreshToken(saved.token(), saved.userId(), saved.expiryDate(), true));
        assertThat(store.revoke(saved.token())).isFalse();
    }

    @Test
    void revokeDeTokenInconnu() {
        assertThat(store.revoke("inconnu")).isFalse();
        assertThat(store.revoke(null)).isFalse();
    }

    @Test
    void deleteByUserIdNeToucheQueLesTokensDeLUtilisateur() {
        StoredRefreshToken deSept = store.save(7L, Instant.now().plusSeconds(60));
        StoredRefreshToken deHuit = store.save(8L, Instant.now().plusSeconds(60));

        assertThat(store.deleteByUserId(7L)).isEqualTo(1);
        assertThat(store.findByToken(deSept.token())).isEmpty();
        assertThat(store.findByToken(deHuit.token())).isPresent();
    }

    @Test
    void deleteExpiredSupprimeLesTokensExpirésSeuls() {
        StoredRefreshToken expire = store.save(7L, Instant.now().minusSeconds(10));
        StoredRefreshToken valide = store.save(7L, Instant.now().plusSeconds(60));

        assertThat(store.deleteExpired(Instant.now())).isEqualTo(1);
        assertThat(store.findByToken(expire.token())).isEmpty();
        assertThat(store.findByToken(valide.token())).isPresent();
    }
}
