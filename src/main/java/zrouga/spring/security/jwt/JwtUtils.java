package zrouga.spring.security.jwt;

import java.util.Base64;
import java.util.Date;

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

    /**
     * Génère un JWT signé HS512 depuis le principal (les rôles et le statut sont portés
     * par {@link UserDetailsImpl}).
     *
     * @param userPrincipal le principal authentifié
     * @return le jeton compact
     */
    public String generateJwtToken(UserDetailsImpl userPrincipal) {
        return Jwts.builder()
                .setId(java.util.UUID.randomUUID().toString())
                .setSubject(userPrincipal.getUsername())
                .setIssuedAt(new Date())
                .claim("id", userPrincipal.getId())
                .claim("email", userPrincipal.getEmail())
                .claim("roles", userPrincipal.getRoles())
                .claim("status", userPrincipal.getStatus())
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
            logger.debug("Jeton JWT expiré : {}", e.getMessage());
            return null;
        } catch (JwtException | IllegalArgumentException e) {
            logger.debug("Jeton JWT invalide : {}", e.getMessage());
            return null;
        }
    }

    /**
     * Génère le challenge éphémère échangé contre les tokens quand la 2FA est
     * active ({@code two-factor-challenge-ttl-ms}, 5 min par défaut) — porteur
     * du claim {@code 2fa} et du sujet (e-mail).
     *
     * @param email e-mail du compte à vérifier
     * @return le jeton compact
     */
    public String generateTwoFactorChallengeToken(String email) {
        return Jwts.builder()
                .setId(java.util.UUID.randomUUID().toString())
                .setSubject(email)
                .setIssuedAt(new Date())
                .claim("2fa", true)
                .setExpiration(new Date(System.currentTimeMillis() + properties.getTwoFactorChallengeTtlMs()))
                .signWith(secretKey, Jwts.SIG.HS512)
                .compact();
    }
}
