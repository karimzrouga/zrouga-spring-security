package zrouga.spring.security.totp;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Instant;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * TOTP (RFC 6238) et Base32 (RFC 4648) — implémentation sans dépendance
 * externe, compatible Google Authenticator, Authy, 1Password, …
 *
 * <p>Paramètres fixes : SHA-1, 6 chiffres, pas de 30 s, fenêtre de
 * vérification ±1 pas (tolérance d'horloge).</p>
 */
public final class Totp {

    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private static final int DIGITS = 6;

    private static final long PERIOD_SECONDS = 30;

    private static final int WINDOW = 1;

    private static final SecureRandom RANDOM = new SecureRandom();

    private Totp() {
    }

    /** Génère un secret Base32 de 160 bits (recommandation RFC 4226 §4). */
    public static String generateSecret() {
        byte[] bytes = new byte[20];
        RANDOM.nextBytes(bytes);
        return encode(bytes);
    }

    /**
     * URI {@code otpauth://totp/…} à encoder en QR côté front (aucune
     * dépendance de QR dans le starter).
     *
     * @param email  compte (label)
     * @param secret secret Base32
     * @param issuer nom de l'application affiché dans l'authenticator
     */
    public static String otpauthUri(String email, String secret, String issuer) {
        String safeIssuer = (issuer == null || issuer.isBlank()) ? "zrouga" : issuer;
        String label = urlEncode(safeIssuer + ":" + email);
        return "otpauth://totp/" + label
                + "?secret=" + secret
                + "&issuer=" + urlEncode(safeIssuer)
                + "&digits=" + DIGITS
                + "&period=" + PERIOD_SECONDS;
    }

    /**
     * Vérifie un code à 6 chiffres contre le secret, à l'instant courant
     * (fenêtre ±1 pas de 30 s).
     *
     * @param code   saisi par l'utilisateur
     * @param secret secret Base32 de l'utilisateur
     * @return {@code true} si le code correspond
     */
    public static boolean verify(String code, String secret) {
        if (code == null || secret == null) {
            return false;
        }
        String trimmed = code.trim();
        if (trimmed.length() != DIGITS || !trimmed.chars().allMatch(c -> c >= '0' && c <= '9')) {
            return false;
        }
        try {
            decode(secret);
        } catch (IllegalArgumentException e) {
            return false;
        }
        long counter = Instant.now().getEpochSecond() / PERIOD_SECONDS;
        for (long i = counter - WINDOW; i <= counter + WINDOW; i++) {
            if (codeAt(secret, i).equals(trimmed)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Code attendu pour un compteur donné (visible pour les tests RFC 6238
     * et les intégrations à horloge contrôlée).
     *
     * @param secret  secret Base32
     * @param counter compteur = secondes UNIX / 30
     * @return le code à 6 chiffres
     */
    public static String codeAt(String secret, long counter) {
        byte[] key = decode(secret);
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] data = new byte[8];
            for (int i = 7; i >= 0; i--) {
                data[i] = (byte) (counter & 0xFF);
                counter >>>= 8;
            }
            byte[] hash = mac.doFinal(data);
            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);
            return String.format("%0" + DIGITS + "d", binary % 1_000_000);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA1 indisponible", e);
        }
    }

    /** Encodage Base32 RFC 4648 sans padding. */
    public static String encode(byte[] data) {
        StringBuilder sb = new StringBuilder((data.length * 8 + 4) / 5);
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                sb.append(ALPHABET.charAt((buffer >>> (bitsLeft - 5)) & 0x1F));
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            sb.append(ALPHABET.charAt((buffer << (5 - bitsLeft)) & 0x1F));
        }
        return sb.toString();
    }

    /** Décodage Base32 RFC 4648 (padding {@code =} toléré). */
    public static byte[] decode(String encoded) {
        if (encoded == null) {
            throw new IllegalArgumentException("secret Base32 absent");
        }
        String normalized = encoded.trim().replace("=", "").replace(" ", "").toUpperCase(java.util.Locale.ROOT);
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("secret Base32 vide");
        }
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream((normalized.length() * 5) / 8);
        int buffer = 0;
        int bitsLeft = 0;
        for (char c : normalized.toCharArray()) {
            int value = ALPHABET.indexOf(c);
            if (value < 0) {
                throw new IllegalArgumentException("caractère Base32 invalide : " + c);
            }
            buffer = (buffer << 5) | value;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                out.write((buffer >>> (bitsLeft - 8)) & 0xFF);
                bitsLeft -= 8;
            }
        }
        return out.toByteArray();
    }

    private static String urlEncode(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8)
                .replace("+", "%20");
    }
}
