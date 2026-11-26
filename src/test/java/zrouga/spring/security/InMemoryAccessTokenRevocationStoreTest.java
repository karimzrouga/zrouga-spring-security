package zrouga.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;

import org.junit.jupiter.api.Test;

class InMemoryAccessTokenRevocationStoreTest {

    private final InMemoryAccessTokenRevocationStore store = new InMemoryAccessTokenRevocationStore();

    @Test
    void jetonRevoqueEstDetecte() {
        store.revoke("jti-1", Instant.now().plusSeconds(60));

        assertThat(store.isRevoked("jti-1")).isTrue();
    }

    @Test
    void jetonInconnuNestPasRevoque() {
        assertThat(store.isRevoked("jamais-vu")).isFalse();
        assertThat(store.isRevoked(null)).isFalse();
    }

    @Test
    void expirationPasseeNEstPlusRevoquee() {
        store.revoke("jti-expire", Instant.now().minusSeconds(1));

        // Le parseur JWT refuse déjà un jeton expiré : l'entrée n'a plus d'effet.
        assertThat(store.isRevoked("jti-expire")).isFalse();
    }

    @Test
    void nullsSansEffet() {
        store.revoke(null, Instant.now().plusSeconds(60));
        store.revoke("jti-null-exp", null);

        assertThat(store.isRevoked(null)).isFalse();
        assertThat(store.isRevoked("jti-null-exp")).isFalse();
    }
}
