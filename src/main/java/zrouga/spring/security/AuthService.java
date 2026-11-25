package zrouga.spring.security;

import java.util.Optional;

import zrouga.spring.security.exception.EmailAlreadyUsedException;
import zrouga.spring.security.exception.SignupNotSupportedException;
import zrouga.spring.security.exception.TokenRefreshException;
import zrouga.spring.security.jwt.JwtUtils;
import zrouga.spring.security.payload.JwtResponse;
import zrouga.spring.security.payload.LoginRequest;
import zrouga.spring.security.payload.MessageResponse;
import zrouga.spring.security.payload.SignupRequest;
import zrouga.spring.security.payload.TokenRefreshRequest;
import zrouga.spring.security.payload.TokenRefreshResponse;
import zrouga.spring.security.ratelimit.LoginRateLimiter;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;

public class AuthService {

    private static final String REFRESH_UNKNOWN_MESSAGE = "Refresh token is not in database!";

    private final AuthenticationManager authenticationManager;
    private final ObjectProvider<AuthUserProvider> userProvider;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;
    private final LoginRateLimiter rateLimiter;
    private final PasswordEncoder passwordEncoder;
    private final ObjectProvider<AuthUserCreator> creatorProvider;
    private final AccountLockoutService accountLockout;
    private final PasswordPolicy passwordPolicy;

    public AuthService(
            AuthenticationManager authenticationManager,
            ObjectProvider<AuthUserProvider> userProvider,
            JwtUtils jwtUtils,
            RefreshTokenService refreshTokenService,
            LoginRateLimiter rateLimiter,
            PasswordEncoder passwordEncoder,
            ObjectProvider<AuthUserCreator> creatorProvider,
            AccountLockoutService accountLockout,
            PasswordPolicy passwordPolicy) {
        this.authenticationManager = authenticationManager;
        this.userProvider = userProvider;
        this.jwtUtils = jwtUtils;
        this.refreshTokenService = refreshTokenService;
        this.rateLimiter = rateLimiter;
        this.passwordEncoder = passwordEncoder;
        this.creatorProvider = creatorProvider;
        this.accountLockout = accountLockout;
        this.passwordPolicy = passwordPolicy;
    }

    public JwtResponse authenticateUser(LoginRequest loginRequest, String clientIp) {
        String emailKey = "signin:email:" + AuthSupport.rateLimitKey(loginRequest.getEmail());
        String ipKey = "signin:ip:" + clientIp;
        rateLimiter.check(emailKey);
        rateLimiter.checkIp(ipKey);
        accountLockout.check(loginRequest.getEmail());

        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
        } catch (AuthenticationException ex) {
            // Échec (identifiants, compte inconnu ou inactif) : compteur verrouillage —
            // recordFailure lève AccountLockedException (423) dès le seuil atteint.
            accountLockout.recordFailure(loginRequest.getEmail());
            throw ex;
        }

        accountLockout.reset(loginRequest.getEmail());
        rateLimiter.reset(emailKey);
        rateLimiter.reset(ipKey);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        String jwt = jwtUtils.generateJwtToken(userDetails);

        refreshTokenService.deleteByUserId(userDetails.getId());
        StoredRefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

        return new JwtResponse(jwt, refreshToken.token());
    }

    public TokenRefreshResponse refreshtoken(TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        // Corps vide et cookie absente : jeton manquant — même réponse que jeton inconnu
        // (le repli cookie est fait par AuthResource avant l'appel).
        if (!StringUtils.hasText(requestRefreshToken)) {
            throw new TokenRefreshException(REFRESH_UNKNOWN_MESSAGE);
        }

        Optional<StoredRefreshToken> refreshTokenOpt = refreshTokenService.findByToken(requestRefreshToken);

        if (refreshTokenOpt.isEmpty()) {
            throw new TokenRefreshException(REFRESH_UNKNOWN_MESSAGE);
        }

        StoredRefreshToken stored = refreshTokenOpt.get();

        // Jeton déjà révoqué = réutilisation (vol potentiel) : famille entière révoquée.
        if (stored.revoked()) {
            refreshTokenService.deleteByUserId(stored.userId());
            throw new TokenRefreshException(REFRESH_UNKNOWN_MESSAGE);
        }

        StoredRefreshToken verified = refreshTokenService.verifyExpiration(stored);
        AuthUser user = provider().findById(verified.userId())
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with id: " + verified.userId()));

        UserDetailsImpl userDetailsImpl = UserDetailsImpl.build(user);

        String token = jwtUtils.generateJwtToken(userDetailsImpl);

        // Rotation atomique : false = un concurrent a déjà tourné ce jeton.
        if (!refreshTokenService.revoke(verified.token())) {
            refreshTokenService.deleteByUserId(verified.userId());
            throw new TokenRefreshException(REFRESH_UNKNOWN_MESSAGE);
        }

        StoredRefreshToken rotated = refreshTokenService.createRefreshToken(verified.userId());

        return new TokenRefreshResponse(token, rotated.token());
    }

    public MessageResponse signup(SignupRequest request, String clientIp) {
        AuthUserCreator creator = creatorProvider.getIfAvailable();
        if (creator == null) {
            throw new SignupNotSupportedException(
                    "Signup is not configured: declare an AuthUserCreator bean to enable POST /api/auth/signup.");
        }

        // Politique de mot de passe avant toute autre vérification : un mot de passe
        // faible est refusé (400 weak_password) quel que soit l'e-mail — uniforme,
        // aucune fuite sur l'existence du compte.
        passwordPolicy.validate(request.getPassword());

        String emailKey = "signup:email:" + AuthSupport.rateLimitKey(request.getEmail());
        String ipKey = "signup:ip:" + clientIp;
        rateLimiter.check(emailKey);
        rateLimiter.checkIp(ipKey);

        if (provider().findByEmail(request.getEmail()).isPresent()) {
            // Hash factice : coût identique au chemin nominal (409 indistinguable par timing).
            passwordEncoder.encode(request.getPassword());
            throw new EmailAlreadyUsedException("Email already in use: " + request.getEmail());
        }

        creator.create(request.getEmail(), passwordEncoder.encode(request.getPassword()));
        rateLimiter.reset(emailKey);
        rateLimiter.reset(ipKey);
        return new MessageResponse("User registered successfully!");
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
        return AuthSupport.provider(userProvider);
    }
}
