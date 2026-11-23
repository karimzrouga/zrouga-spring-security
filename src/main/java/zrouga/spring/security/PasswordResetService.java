package zrouga.spring.security;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.Optional;

import zrouga.spring.security.exception.InvalidResetTokenException;
import zrouga.spring.security.exception.PasswordResetNotSupportedException;
import zrouga.spring.security.payload.ForgotPasswordRequest;
import zrouga.spring.security.payload.MessageResponse;
import zrouga.spring.security.payload.ResetPasswordRequest;
import zrouga.spring.security.ratelimit.LoginRateLimiter;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Réinitialisation du mot de passe par e-mail — fonctionnalité <b>optionnelle</b>,
 * active uniquement si {@code zrouga.security.reset-enabled=true}.
 *
 * <p>Flux : {@code /forgot-password} génère un jeton usage unique (15 min par défaut),
 * l'e-mail SMTP contient le lien {@code reset-base-url?token=…} ; {@code /reset-password}
 * consomme le jeton <b>avant</b> toute mutation (claim first), enregistre le nouveau hash
 * via {@link AuthUserPasswordUpdater} et révoque tous les refresh tokens du compte.</p>
 *
 * <p>Anti-énumération : {@code /forgot-password} répond toujours le même message,
 * que l'e-mail existe ou non.</p>
 */
public class PasswordResetService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final ZrougaSecurityProperties properties;
    private final ObjectProvider<AuthUserProvider> userProvider;
    private final ObjectProvider<AuthUserPasswordUpdater> passwordUpdater;
    private final ObjectProvider<PasswordResetEmailSender> emailSender;
    private final PasswordResetTokenStore tokenStore;
    private final RefreshTokenService refreshTokenService;
    private final LoginRateLimiter rateLimiter;
    private final PasswordEncoder passwordEncoder;

    public PasswordResetService(
            ZrougaSecurityProperties properties,
            ObjectProvider<AuthUserProvider> userProvider,
            ObjectProvider<AuthUserPasswordUpdater> passwordUpdater,
            ObjectProvider<PasswordResetEmailSender> emailSender,
            PasswordResetTokenStore tokenStore,
            RefreshTokenService refreshTokenService,
            LoginRateLimiter rateLimiter,
            PasswordEncoder passwordEncoder) {
        this.properties = properties;
        this.userProvider = userProvider;
        this.passwordUpdater = passwordUpdater;
        this.emailSender = emailSender;
        this.tokenStore = tokenStore;
        this.refreshTokenService = refreshTokenService;
        this.rateLimiter = rateLimiter;
        this.passwordEncoder = passwordEncoder;
        validateWhenEnabled();
    }

    /**
     * Demande l'envoi de l'e-mail de réinitialisation.
     *
     * <p>Toujours 200 avec le même message (existence du compte non révélée) ; le
     * rate-limit s'applique par e-mail <b>et</b> par IP (compte connu ou non) et n'est
     * jamais réinitialisé. Un seul jeton actif par compte.</p>
     *
     * @param request  la demande
     * @param clientIp IP du client (rate-limit)
     */
    public MessageResponse forgotPassword(ForgotPasswordRequest request, String clientIp) {
        requireEnabled();

        String email = request.getEmail();
        rateLimiter.check("forgot:email:" + rateLimitKey(email));
        rateLimiter.checkIp("forgot:ip:" + clientIp);

        provider().findByEmail(email).ifPresent(user -> {
            tokenStore.deleteByEmail(email);
            String rawToken = generateToken();
            Instant expiry = Instant.now().plusMillis(properties.getResetTokenExpirationMs());
            tokenStore.save(new StoredResetToken(rawToken, email, expiry));
            sender().send(email, rawToken);
        });

        return new MessageResponse("If the account exists, a reset email has been sent.");
    }

    /**
     * Consomme le jeton et enregistre le nouveau mot de passe (usage unique, jeton 15 min).
     *
     * @param request  la demande
     * @param clientIp IP du client (rate-limit anti-force brute du jeton)
     */
    public MessageResponse resetPassword(ResetPasswordRequest request, String clientIp) {
        requireEnabled();

        rateLimiter.checkIp("reset:ip:" + clientIp);

        String rawToken = request.getToken();
        StoredResetToken stored = tokenStore.findByToken(rawToken)
                .orElseThrow(() -> invalidToken());
        if (stored.expiry().isBefore(Instant.now())) {
            tokenStore.consume(rawToken);
            throw invalidToken();
        }

        AuthUser user = provider().findByEmail(stored.email())
                .orElseThrow(() -> invalidToken());

        // Claim first : un seul concurrent peut consommer le jeton.
        if (!tokenStore.consume(rawToken)) {
            throw invalidToken();
        }

        updater().updatePassword(stored.email(), passwordEncoder.encode(request.getPassword()));
        refreshTokenService.deleteByUserId(user.getId());

        return new MessageResponse("Password has been reset successfully.");
    }

    private void validateWhenEnabled() {
        if (!properties.isResetEnabled()) {
            return;
        }
        if (properties.getResetBaseUrl() == null || properties.getResetBaseUrl().isBlank()) {
            throw new IllegalStateException(
                    "zrouga.security.reset-enabled=true : zrouga.security.reset-base-url est obligatoire "
                            + "(URL de la page de réinitialisation côté front).");
        }
        if (passwordUpdater.getIfAvailable() == null) {
            throw new IllegalStateException(
                    "zrouga.security.reset-enabled=true : aucun bean AuthUserPasswordUpdater déclaré. "
                            + "Implémentez zrouga.spring.security.AuthUserPasswordUpdater et déclarez-la "
                            + "comme @Component ou @Bean.");
        }
        if (emailSender.getIfAvailable() == null) {
            throw new IllegalStateException(
                    "zrouga.security.reset-enabled=true : aucun bean PasswordResetEmailSender disponible.");
        }
    }

    private void requireEnabled() {
        if (!properties.isResetEnabled()) {
            throw new PasswordResetNotSupportedException(
                    "Reset password non active : activez zrouga.security.reset-enabled=true "
                            + "(et configurez reset-base-url, spring.mail.* et AuthUserPasswordUpdater).");
        }
    }

    private InvalidResetTokenException invalidToken() {
        return new InvalidResetTokenException("Invalid or expired reset token.");
    }

    private AuthUserProvider provider() {
        AuthUserProvider provider = userProvider.getIfAvailable();
        if (provider == null) {
            throw new IllegalStateException(AuthUserProvider.MISSING_BEAN_MESSAGE);
        }
        return provider;
    }

    private AuthUserPasswordUpdater updater() {
        AuthUserPasswordUpdater updater = passwordUpdater.getIfAvailable();
        if (updater == null) {
            throw new IllegalStateException(
                    "zrouga.spring.security : aucun bean AuthUserPasswordUpdater déclaré.");
        }
        return updater;
    }

    private PasswordResetEmailSender sender() {
        PasswordResetEmailSender sender = emailSender.getIfAvailable();
        if (sender == null) {
            throw new IllegalStateException(
                    "zrouga.spring.security : aucun bean PasswordResetEmailSender déclaré.");
        }
        return sender;
    }

    private static String generateToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String rateLimitKey(String email) {
        return email == null ? "" : email.toLowerCase(Locale.ROOT);
    }
}
