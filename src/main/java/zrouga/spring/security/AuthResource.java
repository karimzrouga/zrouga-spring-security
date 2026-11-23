package zrouga.spring.security;

import zrouga.spring.security.payload.ForgotPasswordRequest;
import zrouga.spring.security.payload.LoginRequest;
import zrouga.spring.security.payload.ResetPasswordRequest;
import zrouga.spring.security.payload.SignupRequest;
import zrouga.spring.security.payload.TokenRefreshRequest;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/api/auth", produces = MediaType.APPLICATION_JSON_VALUE)
public class AuthResource {

    private final AuthService authService;
    private final PasswordResetService passwordResetService;
    private final ZrougaSecurityProperties properties;

    public AuthResource(AuthService authService, PasswordResetService passwordResetService,
            ZrougaSecurityProperties properties) {
        this.authService = authService;
        this.passwordResetService = passwordResetService;
        this.properties = properties;
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest,
            HttpServletRequest http) {
        return ResponseEntity.ok(authService.authenticateUser(loginRequest, clientIp(http)));
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

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordRequest request,
            HttpServletRequest http) {
        return ResponseEntity.ok(passwordResetService.resetPassword(request, clientIp(http)));
    }

    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshtoken(@Valid @RequestBody TokenRefreshRequest request) {
        return ResponseEntity.ok(authService.refreshtoken(request));
    }

    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser() {
        return ResponseEntity.ok(authService.logoutUser());
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
}
