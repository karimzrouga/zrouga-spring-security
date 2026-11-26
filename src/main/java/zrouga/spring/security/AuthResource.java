package zrouga.spring.security;

import zrouga.spring.security.payload.ForgotPasswordRequest;
import zrouga.spring.security.payload.JwtResponse;
import zrouga.spring.security.payload.LoginRequest;
import zrouga.spring.security.payload.MessageResponse;
import zrouga.spring.security.payload.ResendVerificationRequest;
import zrouga.spring.security.payload.ResetPasswordRequest;
import zrouga.spring.security.payload.SignupRequest;
import zrouga.spring.security.payload.TokenRefreshRequest;
import zrouga.spring.security.payload.TokenRefreshResponse;
import zrouga.spring.security.payload.TwoFactorCodeRequest;
import zrouga.spring.security.payload.TwoFactorVerifyRequest;
import zrouga.spring.security.payload.VerifyEmailRequest;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/api/auth", produces = MediaType.APPLICATION_JSON_VALUE)
public class AuthResource {

    private final AuthService authService;
    private final PasswordResetService passwordResetService;
    private final EmailVerificationService emailVerificationService;
    private final ZrougaSecurityProperties properties;

    public AuthResource(AuthService authService, PasswordResetService passwordResetService,
            EmailVerificationService emailVerificationService, ZrougaSecurityProperties properties) {
        this.authService = authService;
        this.passwordResetService = passwordResetService;
        this.emailVerificationService = emailVerificationService;
        this.properties = properties;
    }

    @Deprecated
    public AuthResource(AuthService authService, PasswordResetService passwordResetService,
            ZrougaSecurityProperties properties) {
        this(authService, passwordResetService,
                new EmailVerificationService(properties, null, null, null,
                        new InMemoryEmailVerificationTokenStore(), null, event -> { }),
                properties);
    }

    /**
     * Connexion — en mode {@code header} renvoie les tokens en JSON (état) ;
     * en mode {@code cookie} met en plus les cookies {@code zrouga_access} /
     * {@code zrouga_refresh} (le corps JSON reste identique).
     */
    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest,
            HttpServletRequest http, HttpServletResponse response) {
        JwtResponse jwtResponse = authService.authenticateUser(loginRequest, clientIp(http), userAgent(http));
        // Challenge 2FA : aucun token à émettre, donc aucune cookie.
        if (cookieMode() && !Boolean.TRUE.equals(jwtResponse.twoFactorRequired())) {
            AuthCookies.write(response, AuthCookies.access(jwtResponse.token(), properties));
            AuthCookies.write(response, AuthCookies.refresh(jwtResponse.refreshToken(), properties));
        }
        return ResponseEntity.ok(jwtResponse);
    }

    /** Étape 1 2FA : secret TOTP + URI otpauth (à encoder en QR côté front). */
    @PostMapping("/2fa/setup")
    public ResponseEntity<?> twoFactorSetup() {
        return ResponseEntity.ok(authService.setupTwoFactor());
    }

    /** Étape 2 2FA : valide un code et active le challenge au signin. */
    @PostMapping("/2fa/enable")
    public ResponseEntity<?> twoFactorEnable(@Valid @RequestBody TwoFactorCodeRequest request) {
        return ResponseEntity.ok(authService.enableTwoFactor(request));
    }

    /** Désactive la 2FA (code TOTP requis). */
    @PostMapping("/2fa/disable")
    public ResponseEntity<?> twoFactorDisable(@Valid @RequestBody TwoFactorCodeRequest request) {
        return ResponseEntity.ok(authService.disableTwoFactor(request));
    }

    /**
     * Échange le challenge 2FA reçu au signin contre les tokens — en mode
     * {@code cookie}, les deux cookies sont émis ici (jamais au signin).
     */
    @PostMapping("/2fa/verify")
    public ResponseEntity<?> twoFactorVerify(@Valid @RequestBody TwoFactorVerifyRequest request,
            HttpServletRequest http, HttpServletResponse response) {
        JwtResponse tokens = authService.verifyTwoFactor(request, clientIp(http), userAgent(http));
        if (cookieMode()) {
            AuthCookies.write(response, AuthCookies.access(tokens.token(), properties));
            AuthCookies.write(response, AuthCookies.refresh(tokens.refreshToken(), properties));
        }
        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupRequest signupRequest, HttpServletRequest http) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.signup(signupRequest, clientIp(http)));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request,
            HttpServletRequest http) {
        return ResponseEntity.ok(passwordResetService.forgotPassword(request, clientIp(http)));
    }

    /**
     * Vérification de l'e-mail — consomme le jeton reçu par e-mail et marque le
     * compte comme vérifié (via {@code AuthUserEmailVerifier}).
     */
    @PostMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@Valid @RequestBody VerifyEmailRequest request,
            HttpServletRequest http) {
        return ResponseEntity.ok(emailVerificationService.verify(request, clientIp(http)));
    }

    /** Renvoie un jeton de vérification neuf — même réponse si le compte n'existe pas. */
    @PostMapping("/resend-verification")
    public ResponseEntity<?> resendVerification(@Valid @RequestBody ResendVerificationRequest request,
            HttpServletRequest http) {
        return ResponseEntity.ok(emailVerificationService.resendVerification(request, clientIp(http)));
    }

    /**
     * Réinitialisation — en mode {@code cookie}, les cookies d'auth sont vidés :
     * tous les refresh tokens du compte sont révoqués, les cookies en circulation
     * deviennent invalides.
     */
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordRequest request,
            HttpServletRequest http, HttpServletResponse response) {
        MessageResponse message = passwordResetService.resetPassword(request, clientIp(http));
        if (cookieMode()) {
            clearAuthCookies(response);
        }
        return ResponseEntity.ok(message);
    }

    /**
     * Rotation du refresh token — lit le jeton dans le corps JSON <b>ou</b>, à défaut,
     * dans la cookie {@code zrouga_refresh} (mode {@code cookie} : le HttpOnly empêche
     * le front de le remettre dans le corps). En mode {@code cookie}, les nouveaux
     * tokens réémettent les deux cookies (rotation invisible pour le navigateur).
     */
    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshtoken(@Valid @RequestBody TokenRefreshRequest request,
            HttpServletRequest http, HttpServletResponse response) {
        if (!StringUtils.hasText(request.getRefreshToken())) {
            request.setRefreshToken(AuthCookies.read(http, AuthCookies.REFRESH_COOKIE));
        }
        TokenRefreshResponse tokens = authService.refreshtoken(request, clientIp(http), userAgent(http));
        if (cookieMode()) {
            AuthCookies.write(response, AuthCookies.access(tokens.accessToken(), properties));
            AuthCookies.write(response, AuthCookies.refresh(tokens.refreshToken(), properties));
        }
        return ResponseEntity.ok(tokens);
    }

    /**
     * Déconnexion — révoque les refresh tokens du compte (et l'access token
     * présenté si {@code revocation-enabled}) ; en mode {@code cookie}, vide les
     * deux cookies d'auth.
     */
    @Deprecated
    public ResponseEntity<?> logoutUser(HttpServletResponse response) {
        MessageResponse message = authService.logoutUser(null);
        if (cookieMode()) {
            clearAuthCookies(response);
        }
        return ResponseEntity.ok(message);
    }

    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser(HttpServletRequest http, HttpServletResponse response) {
        MessageResponse message = authService.logoutUser(extractAccessToken(http));
        if (cookieMode()) {
            clearAuthCookies(response);
        }
        return ResponseEntity.ok(message);
    }

    /** Access token brut (header Bearer ou cookie {@code zrouga_access}), ou {@code null}. */
    private String extractAccessToken(HttpServletRequest http) {
        String headerAuth = http.getHeader("Authorization");
        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }
        return AuthCookies.read(http, AuthCookies.ACCESS_COOKIE);
    }

    private boolean cookieMode() {
        return "cookie".equalsIgnoreCase(properties.getAuthMode());
    }

    private void clearAuthCookies(HttpServletResponse response) {
        AuthCookies.write(response, AuthCookies.cleared(AuthCookies.ACCESS_COOKIE, "/", properties));
        AuthCookies.write(response, AuthCookies.cleared(AuthCookies.REFRESH_COOKIE, AuthCookies.REFRESH_PATH,
                properties));
    }

    /**
     * IP réelle du client pour le rate-limit. {@code X-Forwarded-For} n'est lu que si
     * {@code zrouga.security.trust-forwarded-for=true} (proxy de confiance) — sinon il
     * serait falsifiable par le client.
     */
    private String clientIp(HttpServletRequest request) {
        if (properties.isTrustForwardedFor()) {
            String forwarded = request.getHeader("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                int comma = forwarded.indexOf(',');
                String first = comma > 0 ? forwarded.substring(0, comma) : forwarded;
                String trimmed = first.trim();
                if (!trimmed.isEmpty()) {
                    return trimmed;
                }
            }
        }
        return request.getRemoteAddr();
    }

    /** User-Agent du client (binding optionnel du refresh token), ou {@code null}. */
    private String userAgent(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        return StringUtils.hasText(userAgent) ? userAgent : null;
    }
}
