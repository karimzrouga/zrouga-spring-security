package zrouga.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import zrouga.spring.security.jwt.JwtUtils;

import javax.crypto.SecretKey;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;

class JwtUtilsTest {

    private record SimpleUser(Long id, String email, String password, List<String> roles, Boolean status)
            implements AuthUser {

        @Override
        public Long getId() {
            return id;
        }

        @Override
        public String getEmail() {
            return email;
        }

        @Override
        public String getPassword() {
            return password;
        }

        @Override
        public List<String> getRoles() {
            return roles;
        }

        @Override
        public Boolean getStatus() {
            return status;
        }
    }

    private ZrougaSecurityProperties properties(long expirationMs) {
        ZrougaSecurityProperties properties = new ZrougaSecurityProperties();
        properties.setJwtSecret(TestSecret.SECRET);
        properties.setJwtExpirationMs(expirationMs);
        return properties;
    }

    private ZrougaSecurityProperties propertiesWithSecret(String secret) {
        ZrougaSecurityProperties properties = new ZrougaSecurityProperties();
        properties.setJwtSecret(secret);
        return properties;
    }

    private SimpleUser user() {
        return new SimpleUser(1L, "admin@test.com", "hash", List.of("ADMIN", "AQP"), true);
    }

    private SecretKey key(String secret) {
        return Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret));
    }

    @Test
    void genereUnJetonValideAvecLesClaimsAttendus() {
        JwtUtils jwtUtils = new JwtUtils(properties(3_600_000L));
        SimpleUser user = user();

        String token = jwtUtils.generateJwtToken(UserDetailsImpl.build(user));

        assertThat(token).isNotBlank();
        assertThat(jwtUtils.parseClaims(token)).isNotNull();
        assertThat(jwtUtils.parseClaims(token).getSubject()).isEqualTo("admin@test.com");

        Claims claims = Jwts.parser().verifyWith(key(TestSecret.SECRET)).build().parseSignedClaims(token)
                .getPayload();
        assertThat(claims.getSubject()).isEqualTo("admin@test.com");
        assertThat(((Number) claims.get("id")).longValue()).isEqualTo(1L);
        assertThat(claims.get("email")).isEqualTo("admin@test.com");
        assertThat((List<Object>) claims.get("roles")).containsExactly("ADMIN", "AQP");
        assertThat(claims.get("status")).isEqualTo(Boolean.TRUE);
        assertThat(claims.getIssuedAt()).isNotNull();
        assertThat(claims.getIssuedAt()).isBeforeOrEqualTo(new Date());
        assertThat(claims.getExpiration()).isAfter(new Date());
    }

    @Test
    void rejecteUnJetonExpire() {
        JwtUtils jwtUtils = new JwtUtils(properties(-5_000L));
        SimpleUser user = user();

        String token = jwtUtils.generateJwtToken(UserDetailsImpl.build(user));

        assertThat(jwtUtils.parseClaims(token)).isNull();
    }

    @Test
    void rejecteUnJetonAltere() {
        JwtUtils jwtUtils = new JwtUtils(properties(3_600_000L));
        SimpleUser user = user();

        String token = jwtUtils.generateJwtToken(UserDetailsImpl.build(user)) + "x";

        assertThat(jwtUtils.parseClaims(token)).isNull();
    }

    @Test
    void rejecteUnJetonSigneAvecUneAutreCle() {
        String autreSecret = "AUTRESECRET0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        JwtUtils emetteur = new JwtUtils(propertiesWithSecret(autreSecret));
        JwtUtils valideur = new JwtUtils(properties(3_600_000L));
        SimpleUser user = user();

        String token = emetteur.generateJwtToken(UserDetailsImpl.build(user));

        assertThat(valideur.parseClaims(token)).isNull();
    }

    @Test
    void rejecteUnJetonAlgNone() {
        JwtUtils jwtUtils = new JwtUtils(properties(3_600_000L));

        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"sub\":\"admin@test.com\"}".getBytes(StandardCharsets.UTF_8));
        String token = header + "." + payload + ".";

        assertThat(jwtUtils.parseClaims(token)).isNull();
    }

    @Test
    void refuseUnSecretVide() {
        ZrougaSecurityProperties properties = new ZrougaSecurityProperties();

        assertThatThrownBy(() -> new JwtUtils(properties))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("zrouga.security.jwt-secret");
    }

    @Test
    void refuseUnSecretTropCourt() {
        assertThatThrownBy(() -> new JwtUtils(propertiesWithSecret("QUJD")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("64 octets");
    }

    @Test
    void refuseUnSecretNonBase64() {
        assertThatThrownBy(() -> new JwtUtils(propertiesWithSecret("________________________")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Base64");
    }
}
