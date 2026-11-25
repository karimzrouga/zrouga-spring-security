package zrouga.spring.security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;

/**
 * Cookies d'authentification du mode {@code zrouga.security.auth-mode=cookie}
 * (<b>Stateful Session Cookies</b>) — interne au starter.
 *
 * <ul>
 * <li>{@value #ACCESS_COOKIE} — access token JWT, {@code Path=/} (le filtre le lit
 *     sur toutes les routes) ;</li>
 * <li>{@value #REFRESH_COOKIE} — refresh token, {@code Path=/api/auth} (le navigateur
 *     ne l'envoie qu'aux endpoints d'authentification).</li>
 * </ul>
 *
 * <p>Les deux sont {@code HttpOnly} (inaccessibles au JavaScript, protection XSS) ;
 * {@code Secure} et {@code SameSite} viennent de {@code cookie-secure} /
 * {@code cookie-same-site}.</p>
 */
public final class AuthCookies {

    /** Cookie de l'access token ({@code Path=/}). */
    public static final String ACCESS_COOKIE = "zrouga_access";

    /** Cookie du refresh token ({@code Path=/api/auth}). */
    public static final String REFRESH_COOKIE = "zrouga_refresh";

    /** Chemin restreint du cookie de refresh. */
    public static final String REFRESH_PATH = "/api/auth";

    private AuthCookies() {
    }

    /** Cookie d'access token à émettre lors d'une connexion / rotation. */
    public static ResponseCookie access(String jwt, ZrougaSecurityProperties properties) {
        return ResponseCookie.from(ACCESS_COOKIE, jwt)
                .path("/")
                .httpOnly(true)
                .secure(properties.isCookieSecure())
                .sameSite(properties.getCookieSameSite())
                .maxAge(Math.max(1, properties.getJwtExpirationMs() / 1000))
                .build();
    }

    /** Cookie de refresh token à émettre lors d'une connexion / rotation. */
    public static ResponseCookie refresh(String refreshToken, ZrougaSecurityProperties properties) {
        return ResponseCookie.from(REFRESH_COOKIE, refreshToken)
                .path(REFRESH_PATH)
                .httpOnly(true)
                .secure(properties.isCookieSecure())
                .sameSite(properties.getCookieSameSite())
                .maxAge(Math.max(1, properties.getJwtRefreshExpirationMs() / 1000))
                .build();
    }

    /** Cookie à vider (déconnexion, réinitialisation) : valeur vide, {@code Max-Age=0}. */
    public static ResponseCookie cleared(String name, String path, ZrougaSecurityProperties properties) {
        return ResponseCookie.from(name, "")
                .path(path)
                .httpOnly(true)
                .secure(properties.isCookieSecure())
                .sameSite(properties.getCookieSameSite())
                .maxAge(0)
                .build();
    }

    /** Écrit l'en-tête {@code Set-Cookie} de la cookie sur la réponse servlet. */
    public static void write(HttpServletResponse response, ResponseCookie cookie) {
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    /**
     * Lit la valeur d'une cookie de la requête.
     *
     * @return la valeur, ou {@code null} si absente ou vide
     */
    public static String read(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (name.equals(cookie.getName()) && cookie.getValue() != null && !cookie.getValue().isEmpty()) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
