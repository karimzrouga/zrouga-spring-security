package zrouga.spring.security;

import java.util.Optional;

import zrouga.spring.security.event.LockoutEvent;
import zrouga.spring.security.event.SignInEvent;
import zrouga.spring.security.event.SignInFailedEvent;
import zrouga.spring.security.event.SignOutEvent;
import zrouga.spring.security.event.SignUpEvent;
import zrouga.spring.security.event.TokenRefreshedEvent;
import zrouga.spring.security.exception.AccountLockedException;
import zrouga.spring.security.exception.AuthenticationRequiredException;
import zrouga.spring.security.exception.EmailAlreadyUsedException;
import zrouga.spring.security.exception.InvalidTwoFactorCodeException;
import zrouga.spring.security.exception.SignupNotSupportedException;
import zrouga.spring.security.exception.TokenRefreshException;
import zrouga.spring.security.exception.TwoFactorNotSupportedException;
import zrouga.spring.security.exception.TwoFactorTokenException;
import zrouga.spring.security.jwt.JwtUtils;
import zrouga.spring.security.payload.JwtResponse;
import zrouga.spring.security.payload.LoginRequest;
import zrouga.spring.security.payload.MessageResponse;
import zrouga.spring.security.payload.SignupRequest;
import zrouga.spring.security.payload.TokenRefreshRequest;
import zrouga.spring.security.payload.TokenRefreshResponse;
import zrouga.spring.security.payload.TwoFactorCodeRequest;
import zrouga.spring.security.payload.TwoFactorSetupResponse;
import zrouga.spring.security.payload.TwoFactorVerifyRequest;
import zrouga.spring.security.ratelimit.LoginRateLimiter;
import zrouga.spring.security.totp.Totp;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;

import io.jsonwebtoken.Claims;

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
    private final ZrougaSecurityProperties properties;
    private final AccessTokenRevocation accessTokenRevocation;
    private final ApplicationEventPublisher eventPublisher;
    private final TwoFactorSecretStore twoFactorSecretStore;

    public AuthService(
            AuthenticationManager authenticationManager,
            ObjectProvider<AuthUserProvider> userProvider,
            JwtUtils jwtUtils,
            RefreshTokenService refreshTokenService,
            LoginRateLimiter rateLimiter,
            PasswordEncoder passwordEncoder,
            ObjectProvider<AuthUserCreator> creatorProvider,
            AccountLockoutService accountLockout,
            PasswordPolicy passwordPolicy,
            ZrougaSecurityProperties properties,
            AccessTokenRevocation accessTokenRevocation,
            ApplicationEventPublisher eventPublisher,
            TwoFactorSecretStore twoFactorSecretStore) {
        this.authenticationManager = authenticationManager;
        this.userProvider = userProvider;
        this.jwtUtils = jwtUtils;
        this.refreshTokenService = refreshTokenService;
        this.rateLimiter = rateLimiter;
        this.passwordEncoder = passwordEncoder;
        this.creatorProvider = creatorProvider;
        this.accountLockout = accountLockout;
        this.passwordPolicy = passwordPolicy;
        this.properties = properties;
        this.accessTokenRevocation = accessTokenRevocation;
        this.eventPublisher = eventPublisher;
        this.twoFactorSecretStore = twoFactorSecretStore;
    }

    @Deprecated
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
        this(authenticationManager, userProvider, jwtUtils, refreshTokenService, rateLimiter,
                passwordEncoder, creatorProvider, accountLockout, passwordPolicy,
                new ZrougaSecurityProperties(), AccessTokenRevocation.disabled(),
                event -> { }, new InMemoryTwoFactorSecretStore());
    }

    public JwtResponse authenticateUser(LoginRequest loginRequest, String clientIp) {
        return authenticateUser(loginRequest, clientIp, null);
    }

    public JwtResponse authenticateUser(LoginRequest loginRequest, String clientIp, String userAgent) {
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
            eventPublisher.publishEvent(new SignInFailedEvent(loginRequest.getEmail(), clientIp));
            // Échec (identifiants, compte inconnu ou inactif) : compteur verrouillage —
            // recordFailure lève AccountLockedException (423) dès le seuil atteint.
            try {
                accountLockout.recordFailure(loginRequest.getEmail());
            } catch (AccountLockedException locked) {
                eventPublisher.publishEvent(new LockoutEvent(loginRequest.getEmail(), clientIp));
                throw locked;
            }
            throw ex;
        }

        accountLockout.reset(loginRequest.getEmail());
        rateLimiter.reset(emailKey);
        rateLimiter.reset(ipKey);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        // 2FA (two-factor-enabled) : compte activé → challenge au lieu des tokens.
        if (twoFactorPending(userDetails.getEmail())) {
            return JwtResponse.twoFactorChallenge(
                    jwtUtils.generateTwoFactorChallengeToken(userDetails.getEmail()));
        }

        return issueTokens(userDetails, loginRequest.getEmail(), clientIp, userAgent);
    }

    /** Émet access + refresh + SignInEvent — chemin nominal après authentification validée. */
    private JwtResponse issueTokens(UserDetailsImpl userDetails, String email, String clientIp, String userAgent) {
        String jwt = jwtUtils.generateJwtToken(userDetails);

        // Mono-session par défaut : un signin révoque les familles précédentes.
        // concurrent-sessions-enabled : chaque appareil garde sa famille.
        if (!properties.isConcurrentSessionsEnabled()) {
            refreshTokenService.deleteByUserId(userDetails.getId());
        }
        StoredRefreshToken refreshToken = refreshTokenService.createRefreshToken(
                userDetails.getId(), clientIp, userAgent);

        eventPublisher.publishEvent(new SignInEvent(email, userDetails.getId(), clientIp));

        return new JwtResponse(jwt, refreshToken.token());
    }

    private boolean twoFactorPending(String email) {
        if (!properties.isTwoFactorEnabled()) {
            return false;
        }
        return twoFactorSecretStore.findByEmail(email).map(StoredTwoFactorSecret::enabled).orElse(false);
    }

    public TokenRefreshResponse refreshtoken(TokenRefreshRequest request) {
        return refreshtoken(request, null, null);
    }

    public TokenRefreshResponse refreshtoken(TokenRefreshRequest request, String clientIp, String userAgent) {
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

        // Binding IP/UA (refresh-binding-enabled) : changement d'origine = vol
        // potentiel — famille révoquée. Les jetons sans binding restent valides.
        if (properties.isRefreshBindingEnabled() && bindingMismatch(verified, clientIp, userAgent)) {
            refreshTokenService.deleteByUserId(verified.userId());
            throw new TokenRefreshException(REFRESH_UNKNOWN_MESSAGE);
        }

        AuthUser user = provider().findById(verified.userId())
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with id: " + verified.userId()));

        UserDetailsImpl userDetailsImpl = UserDetailsImpl.build(user);

        String token = jwtUtils.generateJwtToken(userDetailsImpl);

        // Rotation atomique : false = un concurrent a déjà tourné ce jeton.
        if (!refreshTokenService.revoke(verified.token())) {
            refreshTokenService.deleteByUserId(verified.userId());
            throw new TokenRefreshException(REFRESH_UNKNOWN_MESSAGE);
        }

        StoredRefreshToken rotated = refreshTokenService.createRefreshToken(verified.userId(), clientIp, userAgent);

        eventPublisher.publishEvent(new TokenRefreshedEvent(verified.userId()));

        return new TokenRefreshResponse(token, rotated.token());
    }

    private static boolean bindingMismatch(StoredRefreshToken stored, String clientIp, String userAgent) {
        if (stored.ip() != null && clientIp != null && !stored.ip().equals(clientIp)) {
            return true;
        }
        return stored.userAgent() != null && userAgent != null && !stored.userAgent().equals(userAgent);
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

        eventPublisher.publishEvent(new SignUpEvent(request.getEmail(), clientIp));

        return new MessageResponse("User registered successfully!");
    }

    /**
     * Étape 1 de la 2FA (authentifié) : génère et stocke un secret TOTP
     * <b>inactif</b> — retourne le secret et l'URI {@code otpauth://} (QR côté
     * front). L'activation ne vient qu'après validation d'un code
     * ({@link #enableTwoFactor(TwoFactorCodeRequest)}).
     */
    public TwoFactorSetupResponse setupTwoFactor() {
        requireTwoFactorEnabled();
        String email = requireCurrentEmail();
        String secret = Totp.generateSecret();
        twoFactorSecretStore.save(email, new StoredTwoFactorSecret(secret, false));
        return new TwoFactorSetupResponse(secret,
                Totp.otpauthUri(email, secret, properties.getTwoFactorIssuer()));
    }

    /**
     * Étape 2 de la 2FA (authentifié) : valide un code TOTP et active le
     * challenge au signin.
     */
    public MessageResponse enableTwoFactor(TwoFactorCodeRequest request) {
        requireTwoFactorEnabled();
        String email = requireCurrentEmail();
        StoredTwoFactorSecret state = twoFactorSecretStore.findByEmail(email)
                .orElseThrow(() -> new InvalidTwoFactorCodeException(
                        "Two-factor setup has not been started: call POST /api/auth/2fa/setup first."));
        if (!Totp.verify(request.code(), state.secret())) {
            throw new InvalidTwoFactorCodeException("Invalid or expired two-factor code.");
        }
        twoFactorSecretStore.save(email, new StoredTwoFactorSecret(state.secret(), true));
        return new MessageResponse("Two-factor authentication enabled.");
    }

    /** Désactive la 2FA du compte courant (code TOTP requis). */
    public MessageResponse disableTwoFactor(TwoFactorCodeRequest request) {
        requireTwoFactorEnabled();
        String email = requireCurrentEmail();
        StoredTwoFactorSecret state = twoFactorSecretStore.findByEmail(email)
                .filter(StoredTwoFactorSecret::enabled)
                .orElseThrow(() -> new InvalidTwoFactorCodeException(
                        "Two-factor authentication is not enabled for this account."));
        if (!Totp.verify(request.code(), state.secret())) {
            throw new InvalidTwoFactorCodeException("Invalid or expired two-factor code.");
        }
        twoFactorSecretStore.delete(email);
        return new MessageResponse("Two-factor authentication disabled.");
    }

    /**
     * Échange le challenge du signin contre les tokens normaux (rate-limité par
     * IP contre la force brute des codes) — même chemin que le signin pour la
     * rotation des familles, le binding et l'événement {@link SignInEvent}.
     */
    public JwtResponse verifyTwoFactor(TwoFactorVerifyRequest request, String clientIp, String userAgent) {
        requireTwoFactorEnabled();

        String rateKey = "2fa:ip:" + clientIp;
        rateLimiter.checkIp(rateKey);

        Claims claims = jwtUtils.parseClaims(request.twoFactorToken());
        if (claims == null || !Boolean.TRUE.equals(claims.get("2fa", Boolean.class))
                || claims.getSubject() == null) {
            throw new TwoFactorTokenException("Invalid or expired two-factor challenge token.");
        }
        String email = claims.getSubject();
        StoredTwoFactorSecret state = twoFactorSecretStore.findByEmail(email)
                .filter(StoredTwoFactorSecret::enabled)
                .orElseThrow(() -> new TwoFactorTokenException(
                        "Invalid or expired two-factor challenge token."));
        if (!Totp.verify(request.code(), state.secret())) {
            throw new InvalidTwoFactorCodeException("Invalid or expired two-factor code.");
        }
        rateLimiter.reset(rateKey);

        AuthUser user = provider().findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with email: " + email));
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities()));

        return issueTokens(userDetails, email, clientIp, userAgent);
    }

    private void requireTwoFactorEnabled() {
        if (!properties.isTwoFactorEnabled()) {
            throw new TwoFactorNotSupportedException(
                    "Two-factor authentication is not enabled: set zrouga.security.two-factor-enabled=true.");
        }
    }

    /** E-mail du principal authentifié — setup/enable/disable exigent un token valide. */
    private String requireCurrentEmail() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth instanceof AnonymousAuthenticationToken
                || !(auth.getPrincipal() instanceof UserDetailsImpl userDetails)) {
            throw new AuthenticationRequiredException(
                    "Authentication required: call this endpoint with a valid access token.");
        }
        return userDetails.getEmail();
    }

    /**
     * Déconnexion — révoque les refresh tokens de l'utilisateur et, si
     * {@code revocation-enabled}, le {@code jti} de l'access token présenté
     * (le JWT devient invalide immédiatement au lieu d'attendre son expiration).
     *
     * @param rawAccessToken access token brut (header ou cookie), ou {@code null}
     */
    public MessageResponse logoutUser(String rawAccessToken) {        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || auth instanceof AnonymousAuthenticationToken) {
            return new MessageResponse("No logged-in user. Nothing to log out.");
        }

        Object principal = auth.getPrincipal();
        if (principal instanceof UserDetailsImpl userDetails) {
            refreshTokenService.deleteByUserId(userDetails.getId());

            if (rawAccessToken != null) {
                Claims claims = jwtUtils.parseClaims(rawAccessToken);
                accessTokenRevocation.revoke(claims);
            }

            eventPublisher.publishEvent(new SignOutEvent(userDetails.getId()));

            return new MessageResponse("Log out successful!");
        }

        return new MessageResponse("Unable to identify user.");
    }

    @Deprecated
    public MessageResponse logoutUser() {
        return logoutUser(null);
    }

    private AuthUserProvider provider() {
        return AuthSupport.provider(userProvider);
    }
}
