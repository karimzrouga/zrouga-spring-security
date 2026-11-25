package zrouga.spring.security;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Historique de mots de passe en mémoire : liste tronquée aux {@code maxRetained}
 * entrées les plus récentes, mises à jour atomiques par compte ({@link Map#compute}).
 *
 * <p>Pas d'éviction automatique : les clés ne sont créées que par une réinitialisation
 * réussie (jeton à usage unique) — le nombre de comptes avec historique est borné par
 * l'usage légitime.</p>
 */
public class InMemoryPasswordHistoryStore implements PasswordHistoryStore {

    private final Map<String, List<String>> history = new ConcurrentHashMap<>();

    @Override
    public List<String> find(String email) {
        List<String> entries = history.get(key(email));
        return entries == null ? List.of() : List.copyOf(entries);
    }

    @Override
    public void record(String email, String encodedPassword, int maxRetained) {
        if (encodedPassword == null || maxRetained <= 0) {
            return;
        }
        history.compute(key(email), (k, current) -> {
            List<String> entries = current == null ? new ArrayList<>() : current;
            entries.add(encodedPassword);
            while (entries.size() > maxRetained) {
                entries.remove(0);
            }
            return entries;
        });
    }

    @Override
    public void delete(String email) {
        history.remove(key(email));
    }

    private static String key(String email) {
        return email == null ? "" : email.toLowerCase(Locale.ROOT);
    }
}
