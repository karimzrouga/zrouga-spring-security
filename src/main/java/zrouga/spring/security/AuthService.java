package zrouga.spring.security;

import java.util.Locale;
import java.util.Optional;

import zrouga.spring.security.exception.TokenRefreshException;
import zrouga.spring.security.jwt.JwtUtils;
import zrouga.spring.security.payload.JwtResponse;
import zrouga.spring.security.payload.LoginRequest;
import zrouga.spring.security.payload.MessageResponse;
import zrouga.spring.security.payload.TokenRefreshRequest;
import zrouga.spring.security.payload.TokenRefreshResponse;
import zrouga.spring.security.ratelimit.LoginRateLimiter;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final ObjectProvider<AuthUserProvider> userProvider;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;
    private final LoginRateLimiter rateLimiter;

    public AuthService(
            AuthenticationManager authenticationManager,
            ObjectProvider<AuthUserProvider> userProvider,
            JwtUtils jwtUtils,
            RefreshTokenService refreshTokenService,
            LoginRateLimiter rateLimiter) {
        this.authenticationManager = authenticationManager;
        this.userProvider = userProvider;
        this.jwtUtils = jwtUtils;
        this.refreshTokenService = refreshTokenService;
        this.rateLimiter = rateLimiter;
    }

    public JwtResponse authenticateUser(LoginRequest loginRequest) {
        String rateLimitKey = rateLimitKey(loginRequest.getEmail());
        rateLimiter.check(rateLimitKey);

        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
        } catch (BadCredentialsException e) {
            rateLimiter.recordFailure(rateLimitKey);
            throw e;
        }
        rateLimiter.reset(rateLimitKey);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        AuthUser user = provider().findById(userDetails.getId())
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with id: " + userDetails.getId()));

        String jwt = jwtUtils.generateJwtToken(userDetails, user);

        refreshTokenService.deleteByUserId(user.getId());

        StoredRefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        return new JwtResponse(jwt, refreshToken.token());
    }

    public TokenRefreshResponse refreshtoken(TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        Optional<StoredRefreshToken> refreshTokenOpt = refreshTokenService.findByToken(requestRefreshToken);

        if (refreshTokenOpt.isEmpty()) {
            throw new TokenRefreshException("Refresh token is not in database!");
        }

        StoredRefreshToken stored = refreshTokenService.verifyExpiration(refreshTokenOpt.get());
        AuthUser user = provider().findById(stored.userId())
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with id: " + stored.userId()));

        UserDetailsImpl userDetailsImpl = UserDetailsImpl.build(user);

        String token = jwtUtils.generateJwtToken(userDetailsImpl, user);

        // Rotation : révoque l'ancien jeton, émet un nouveau — toute réutilisation est refusée.
        refreshTokenService.revoke(stored.token());
        StoredRefreshToken rotated = refreshTokenService.createRefreshToken(user);

        return new TokenRefreshResponse(token, rotated.token());
    }

    public MessageResponse logoutUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || auth instanceof AnonymousAuthenticationToken) {
            return new MessageResponse("No logged-in user. Nothing to log out.");
        }

        Object principal = auth.getPrincipal();
        if (principal instanceof UserDetailsImpl userDetails) {
            refreshTokenService.deleteByUserId(userDetails.getId());
            return new MessageResponse("Log out successful!");
        }

        return new MessageResponse("Unable to identify user.");
    }

    private AuthUserProvider provider() {
        AuthUserProvider provider = userProvider.getIfAvailable();
        if (provider == null) {
            throw new IllegalStateException(AuthUserProvider.MISSING_BEAN_MESSAGE);
        }
        return provider;
    }

    private String rateLimitKey(String email) {
        return email == null ? "" : email.toLowerCase(Locale.ROOT);
    }
}
