package zrouga.spring.security;

/**
 * Secret de test partagé (Base64 valide, 75 octets décodés) — même valeur que
 * {@code src/test/resources/application.properties}.
 */
public final class TestSecret {

    public static final String SECRET =
            "ZROUGATESTSECRET0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private TestSecret() {
    }
}
