package zrouga.spring.security.totp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

class TotpTest {

    /** Secret ASCII de la RFC 6238 (Appendix B), encodé Base32. */
    private static final String RFC_SECRET = Totp
            .encode("12345678901234567890".getBytes(StandardCharsets.US_ASCII));

    @Test
    void vecteursRfc6238SontReproduits() {
        // 8 chiffres de la RFC, tronqués à 6 (les 6 derniers chiffres).
        assertThat(Totp.codeAt(RFC_SECRET, 59L / 30)).isEqualTo("287082");
        assertThat(Totp.codeAt(RFC_SECRET, 1111111109L / 30)).isEqualTo("081804");
        assertThat(Totp.codeAt(RFC_SECRET, 1111111111L / 30)).isEqualTo("050471");
        assertThat(Totp.codeAt(RFC_SECRET, 1234567890L / 30)).isEqualTo("005924");
        assertThat(Totp.codeAt(RFC_SECRET, 2000000000L / 30)).isEqualTo("279037");
        assertThat(Totp.codeAt(RFC_SECRET, 20000000000L / 30)).isEqualTo("353130");
    }

    @Test
    void verifyAccepteLeCodeCourantEtLaFenetre() {
        long counter = System.currentTimeMillis() / 1000 / 30;

        assertThat(Totp.verify(Totp.codeAt(RFC_SECRET, counter), RFC_SECRET)).isTrue();
        assertThat(Totp.verify(Totp.codeAt(RFC_SECRET, counter - 1), RFC_SECRET)).isTrue();
        assertThat(Totp.verify(Totp.codeAt(RFC_SECRET, counter + 1), RFC_SECRET)).isTrue();
    }

    @Test
    void verifyRefuseLesCodesInvalides() {
        long counter = System.currentTimeMillis() / 1000 / 30;
        String wrong = String.format("%06d",
                (Integer.parseInt(Totp.codeAt(RFC_SECRET, counter)) + 500_000) % 1_000_000);

        assertThat(Totp.verify(wrong, RFC_SECRET)).isFalse();
        assertThat(Totp.verify("12345", RFC_SECRET)).isFalse();
        assertThat(Totp.verify("abcdef", RFC_SECRET)).isFalse();
        assertThat(Totp.verify(null, RFC_SECRET)).isFalse();
        assertThat(Totp.verify("123456", "secret invalide!")).isFalse();
    }

    @Test
    void base32EncodeLesVecteursRfc4648() {
        assertThat(Totp.encode(bytes(""))).isEmpty();
        assertThat(Totp.encode("f".getBytes(StandardCharsets.US_ASCII))).isEqualTo("MY");
        assertThat(Totp.encode("fo".getBytes(StandardCharsets.US_ASCII))).isEqualTo("MZXQ");
        assertThat(Totp.encode("foo".getBytes(StandardCharsets.US_ASCII))).isEqualTo("MZXW6");
        assertThat(Totp.encode("foob".getBytes(StandardCharsets.US_ASCII))).isEqualTo("MZXW6YQ");
        assertThat(Totp.encode("fooba".getBytes(StandardCharsets.US_ASCII))).isEqualTo("MZXW6YTB");
        assertThat(Totp.encode("foobar".getBytes(StandardCharsets.US_ASCII))).isEqualTo("MZXW6YTBOI");
    }

    @Test
    void base32DecodeInverseEncodeEtRejetteLeInvalide() {
        byte[] data = "zrouga-security".getBytes(StandardCharsets.US_ASCII);
        assertThat(Totp.decode(Totp.encode(data))).isEqualTo(data);

        assertThatThrownBy(() -> Totp.decode("caractères!")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Totp.decode("")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Totp.decode(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void otpauthUriPorteLeLabelEtLeSecret() {
        String uri = Totp.otpauthUri("user@test.com", "JBSWY3DPEHPK3PXP", "polyvalence");

        assertThat(uri).startsWith("otpauth://totp/polyvalence%3Auser%40test.com")
                .contains("?secret=JBSWY3DPEHPK3PXP")
                .contains("&issuer=polyvalence")
                .contains("&digits=6")
                .contains("&period=30");
    }

    @Test
    void generateSecretProduitDuBase32Valide() {
        String secret = Totp.generateSecret();

        assertThat(secret).hasSize(32);
        assertThat(Totp.decode(secret)).hasSize(20);
        assertThat(secret).matches("[A-Z2-7]+");
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }
}
