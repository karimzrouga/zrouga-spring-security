package zrouga.spring.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Hashage SHA-256 des jetons côté serveur : la persistance (JPA) ne stocke que
 * l'empreinte — une fuite de table ne fournit aucun jeton utilisable.
 *
 * <p>Les implémentations en mémoire gardent le jeton brut (éphémère, sans valeur
 * persistée). Seuls {@code findByToken}/{@code revoke}/{@code consume} reçoivent le
 * brut : le hash n'est jamais exposé à l'extérieur.</p>
 */
public final class TokenHashing {

    private static final ThreadLocal<MessageDigest> SHA_256 = ThreadLocal.withInitial(() -> {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 indisponible", e);
        }
    });

    private TokenHashing() {
    }

    /**
     * @param raw jeton brut (tel que transmis au client)
     * @return empreinte SHA-256 en hexadécimal, ou {@code null} si {@code raw} est nul
     */
    public static String sha256Hex(String raw) {
        if (raw == null) {
            return null;
        }
        return HexFormat.of().formatHex(SHA_256.get().digest(raw.getBytes(StandardCharsets.UTF_8)));
    }
}
