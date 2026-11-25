package zrouga.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Historique de mots de passe en mémoire : lecture, troncature aux
 * {@code maxRetained} plus récents, oubli de l'historique.
 */
class InMemoryPasswordHistoryStoreTest {

    private final InMemoryPasswordHistoryStore store = new InMemoryPasswordHistoryStore();

    @Test
    void findSansHistoriqueRetourneListeVide() {
        assertThat(store.find("inconnu@test.com")).isEmpty();
    }

    @Test
    void recordPuisFindRetourneLesHashs() {
        store.record("a@test.com", "hash-1", 3);
        store.record("a@test.com", "hash-2", 3);

        assertThat(store.find("a@test.com")).containsExactly("hash-1", "hash-2");
    }

    @Test
    void tronqueLesEntreesLesPlusAnciennes() {
        store.record("a@test.com", "hash-1", 2);
        store.record("a@test.com", "hash-2", 2);
        store.record("a@test.com", "hash-3", 2);

        assertThat(store.find("a@test.com")).containsExactly("hash-2", "hash-3");
    }

    @Test
    void maxRetainedZeroOuNullEstNoOp() {
        store.record("a@test.com", "hash-1", 0);
        store.record("a@test.com", null, 5);

        assertThat(store.find("a@test.com")).isEmpty();
    }

    @Test
    void deleteOublieToutLHistorique() {
        store.record("a@test.com", "hash-1", 3);
        store.delete("a@test.com");

        assertThat(store.find("a@test.com")).isEmpty();
    }

    @Test
    void comptesSeparesEtCasseInsensible() {
        store.record("A@Test.com", "hash-a", 3);
        store.record("b@test.com", "hash-b", 3);

        assertThat(store.find("a@test.com")).containsExactly("hash-a");
        assertThat(store.find("B@TEST.COM")).containsExactly("hash-b");
    }

    @Test
    void findRetourneUneCopieInmodifiable() {
        store.record("a@test.com", "hash-1", 3);

        assertThat(store.find("a@test.com")).isUnmodifiable();
    }
}
