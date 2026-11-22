package zrouga.spring.security.jwt;

import java.util.Base64;
import java.util.Date;
import java.util.List;

import zrouga.spring.security.AuthUser;
import zrouga.spring.security.UserDetailsImpl;
import zrouga.spring.security.ZrougaSecurityProperties;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    /** Longueur minimale (en octets) de la clé décodée, exigée par HS512 (RFC 7518). */
    private static final int MIN_SECRET_BYTES = 64;

    private final ZrougaSecurityProperties properties;

    private final SecretKey secretKey;

    private final JwtParser parser;

    public JwtUtils(ZrougaSecurityProperties properties) {
        Assert.hasText(properties.getJwtSecret(), "zrouga.security.jwt-secret doit être renseigné");
        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(properties.getJwtSecret());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(
                    "zrouga.security.jwt-secret doit être un Base64 standard valide (A-Z, a-z, 0-9, +, /, =) — "
                            + "exemple : openssl rand -base64 64");
        }
        if (keyBytes.length < MIN_SECRET_BYTES) {
            throw new IllegalStateException(
                    "zrouga.security.jwt-secret doit décoder à au moins 64 octets (512 bits) pour HS512 — "
                            + "exemple : openssl rand -base64 64");
        }
        this.properties = properties;
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
        this.parser = Jwts.parser().verifyWith(this.secretKey).build();
    }

    public String generateJwtToken(UserDetailsImpl userPrincipal, AuthUser user) {
        List<String> roles = user.getRoles();
        return Jwts.builder()
                .setSubject(userPrincipal.getUsername())
                .claim("id", userPrincipal.getId())
                .claim("email", userPrincipal.getEmail())
                .claim("roles", roles)
                .claim("status", user.getStatus())
                .setExpiration(new Date(System.currentTimeMillis() + properties.getJwtExpirationMs()))
                .signWith(secretKey, Jwts.SIG.HS512)
                .compact();
    }

    /**
     * Analyse et valide un jeton en une seule passe, puis retourne ses claims.
     *
     * @param token le jeton brut
     * @return les claims, ou {@code null} si le jeton est invalide ou expiré
     */
    public Claims parseClaims(String token) {
        try {
            return parser.parseSignedClaims(token).getPayload();
        } catch (ExpiredJwtException e) {
            logger.warn("Jeton JWT expiré : {}", e.getMessage());
            return null;
        } catch (JwtException | IllegalArgumentException e) {
            logger.warn("Jeton JWT invalide : {}", e.getMessage());
            return null;
        }
    }

    public boolean validateJwtToken(String authToken) {
        return parseClaims(authToken) != null;
    }

    public String getUserNameFromJwtToken(String token) {
        return parser.parseSignedClaims(token).getPayload().getSubject();
    }
}
