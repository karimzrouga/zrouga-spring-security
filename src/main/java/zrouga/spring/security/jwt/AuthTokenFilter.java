package zrouga.spring.security.jwt;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

import zrouga.spring.security.UserDetailsImpl;
import zrouga.spring.security.payload.ApiError;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import io.jsonwebtoken.Claims;

public class AuthTokenFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    private final JwtUtils jwtUtils;

    public AuthTokenFilter(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String jwt = parseJwt(request);
            if (jwt != null) {
                Claims claims = jwtUtils.parseClaims(jwt);
                if (claims != null) {
                    Authentication authentication = buildAuthentication(claims, request);
                    if (authentication != null) {
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }
            }
        } catch (Exception e) {
            logger.warn("Impossible de définir l'authentification : {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    private Authentication buildAuthentication(Claims claims, HttpServletRequest request) {
        Object idClaim = claims.get("id");
        String email = claims.get("email", String.class);
        if (!(idClaim instanceof Number) || email == null) {
            return null;
        }

        UserDetailsImpl userDetails = UserDetailsImpl.buildFromToken(
                ((Number) idClaim).longValue(),
                email,
                claims.get("status", Boolean.class),
                extractRoles(claims.get("roles")));

        if (!userDetails.isEnabled()) {
            logger.debug("Compte inactif : authentification refusée pour {}", email);
            return null;
        }

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        return authentication;
    }

    private List<String> extractRoles(Object claim) {
        if (claim instanceof List<?> list) {
            return list.stream().filter(Objects::nonNull).map(String::valueOf).toList();
        }
        return List.of();
    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }

        return null;
    }
}
