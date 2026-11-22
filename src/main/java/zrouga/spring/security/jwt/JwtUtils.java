package zrouga.spring.security.jwt;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import zrouga.spring.security.AuthUser;
import zrouga.spring.security.UserDetailsImpl;
import zrouga.spring.security.ZrougaSecurityProperties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    private final ZrougaSecurityProperties properties;

    public JwtUtils(ZrougaSecurityProperties properties) {
        Assert.hasText(properties.getJwtSecret(), "zrouga.security.jwt-secret doit être renseigné");
        this.properties = properties;
    }

    public String generateJwtToken(UserDetailsImpl userPrincipal, AuthUser user) {
        List<String> roles = userPrincipal.getAuthorities().stream().map(item -> item.getAuthority())
                .collect(Collectors.toList());
        return Jwts.builder().setSubject(userPrincipal.getUsername())
                .claim("id", userPrincipal.getId()).claim("email", userPrincipal.getEmail()).claim("roles", roles)
                .claim("status", user.getStatus())
                .setExpiration(new Date((new Date()).getTime() + properties.getJwtExpirationMs()))
                .signWith(SignatureAlgorithm.HS512, properties.getJwtSecret()).compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(properties.getJwtSecret()).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(properties.getJwtSecret()).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }
}
