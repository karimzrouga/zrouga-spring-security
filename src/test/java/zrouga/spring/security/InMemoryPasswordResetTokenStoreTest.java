package zrouga.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;

import org.junit.jupiter.api.Test;

class InMemoryPasswordResetTokenStoreTest {

    private final InMemoryPasswordResetTokenStore store = new InMemoryPasswordResetTokenStore();

    @Test
    void consumeEstAtomique() {
        store.save(new StoredResetToken("jeton", "a@test.com", Instant.now().plusSeconds(60)));

        assertThat(store.consume("jeton")).isTrue();
        assertThat(store.consume("jeton")).isFalse();
        assertThat(store.consume("inconnu")).isFalse();
        assertThat(store.consume(null)).isFalse();
    }

    @Test
    void deleteByEmailNeToucheQueLesJetonsDuCompte() {
        store.save(new StoredResetToken("de-a", "a@test.com", Instant.now().plusSeconds(60)));
        store.save(new StoredResetToken("de-a-2", "a@test.com", Instant.now().plusSeconds(60)));
        store.save(new StoredResetToken("de-b", "b@test.com", Instant.now().plusSeconds(60)));

        assertThat(store.deleteByEmail("a@test.com")).isEqualTo(2);
        assertThat(store.findByToken("de-a")).isEmpty();
        assertThat(store.findByToken("de-a-2")).isEmpty();
        assertThat(store.findByToken("de-b")).isPresent();
        assertThat(store.deleteByEmail("a@test.com")).isZero();
        assertThat(store.deleteByEmail(null)).isZero();
    }

    @Test
    void deleteExpiredNeToucheQueLesJetonsExpires() {
        store.save(new StoredResetToken("expire", "a@test.com", Instant.now().minusSeconds(10)));
        store.save(new StoredResetToken("valide", "a@test.com", Instant.now().plusSeconds(60)));

        assertThat(store.deleteExpired(Instant.now())).isEqualTo(1);
        assertThat(store.findByToken("expire")).isEmpty();
        assertThat(store.findByToken("valide")).isPresent();
    }

    @Test
    void savePuisFindByTokenRetourneLeJeton() {
        StoredResetToken token = new StoredResetToken("jeton", "a@test.com", Instant.now().plusSeconds(60));

        store.save(token);

        assertThat(store.findByToken("jeton")).contains(token);
    }
}
