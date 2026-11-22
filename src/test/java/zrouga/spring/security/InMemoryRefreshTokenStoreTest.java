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
    void deleteByToken() {
        StoredRefreshToken saved = store.save(7L, Instant.now().plusSeconds(60));

        store.deleteByToken(saved.token());

        assertThat(store.findByToken(saved.token())).isEmpty();
    }

    @Test
    void deleteByUserIdNeToucheQueLesTokensDeLUtilisateur() {
        StoredRefreshToken deSept = store.save(7L, Instant.now().plusSeconds(60));
        StoredRefreshToken deHuit = store.save(8L, Instant.now().plusSeconds(60));

        assertThat(store.deleteByUserId(7L)).isEqualTo(1);
        assertThat(store.findByToken(deSept.token())).isEmpty();
        assertThat(store.findByToken(deHuit.token())).isPresent();
    }
}
