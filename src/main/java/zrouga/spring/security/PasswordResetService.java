package zrouga.spring.security;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

import zrouga.spring.security.exception.InvalidResetTokenException;
import zrouga.spring.security.exception.PasswordResetNotSupportedException;
import zrouga.spring.security.exception.WeakPasswordException;
import zrouga.spring.security.event.PasswordResetEvent;
import zrouga.spring.security.payload.ForgotPasswordRequest;
import zrouga.spring.security.payload.MessageResponse;
import zrouga.spring.security.payload.ResetPasswordRequest;
import zrouga.spring.security.ratelimit.LoginRateLimiter;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Réinitialisation du mot de passe par e-mail — fonctionnalité <b>optionnelle</b>,
 * active uniquement si {@code zrouga.security.reset-enabled=true}.
 *
 * <p>Flux : {@code /forgot-password} génère un jeton usage unique (15 min par défaut),
 * l'e-mail SMTP contient le lien {@code reset-base-url?token=…} ; {@code /reset-password}
 * consomme le jeton <b>avant</b> toute mutation (claim first), enregistre le nouveau hash
 * via {@code AuthUserPasswordUpdater} et révoque tous les refresh tokens du compte.</p>
 *
 * <p>Politique de mot de passe (optionnelle, {@code password-policy-enabled=true}) :
 * le nouveau mot de passe est validé <b>avant</b> la consommation du jeton — un mot de
 * passe refusé ({@code 400 weak_password}) laisse le jeton utilisable pour une nouvelle
 * tentative. Vérifie aussi l'anti-réutilisation : mot de passe courant (hash de
 * {@link AuthUser#getPassword()}) et {@code password-history-count} précédents via
 * {@link PasswordHistoryStore}.</p>
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
    private final PasswordPolicy passwordPolicy;
    private final PasswordHistoryStore passwordHistoryStore;
    private final ApplicationEventPublisher eventPublisher;

    public PasswordResetService(
            ZrougaSecurityProperties properties,
            ObjectProvider<AuthUserProvider> userProvider,
            ObjectProvider<AuthUserPasswordUpdater> passwordUpdater,
            ObjectProvider<PasswordResetEmailSender> emailSender,
            PasswordResetTokenStore tokenStore,
            RefreshTokenService refreshTokenService,
            LoginRateLimiter rateLimiter,
            PasswordEncoder passwordEncoder,
            PasswordPolicy passwordPolicy,
            PasswordHistoryStore passwordHistoryStore,
            ApplicationEventPublisher eventPublisher) {
        this.properties = properties;
        this.userProvider = userProvider;
        this.passwordUpdater = passwordUpdater;
        this.emailSender = emailSender;
        this.tokenStore = tokenStore;
        this.refreshTokenService = refreshTokenService;
        this.rateLimiter = rateLimiter;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicy = passwordPolicy;
        this.passwordHistoryStore = passwordHistoryStore;
        this.eventPublisher = eventPublisher;
        validateWhenEnabled();
    }

    @Deprecated
    public PasswordResetService(
            ZrougaSecurityProperties properties,
            ObjectProvider<AuthUserProvider> userProvider,
            ObjectProvider<AuthUserPasswordUpdater> passwordUpdater,
            ObjectProvider<PasswordResetEmailSender> emailSender,
            PasswordResetTokenStore tokenStore,
            RefreshTokenService refreshTokenService,
            LoginRateLimiter rateLimiter,
            PasswordEncoder passwordEncoder,
            PasswordPolicy passwordPolicy,
            PasswordHistoryStore passwordHistoryStore) {
        this(properties, userProvider, passwordUpdater, emailSender, tokenStore,
                refreshTokenService, rateLimiter, passwordEncoder, passwordPolicy,
                passwordHistoryStore, event -> { });
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
        rateLimiter.check("forgot:email:" + AuthSupport.rateLimitKey(email));
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

        // Politique avant consommation : un mot de passe refusé ne brûle pas le jeton.
        if (properties.isPasswordPolicyEnabled()) {
            passwordPolicy.validate(request.getPassword());
            requireNotReused(stored.email(), request.getPassword(), user.getPassword());
        }

        // Claim first : un seul concurrent peut consommer le jeton.
        if (!tokenStore.consume(rawToken)) {
            throw invalidToken();
        }

        String outgoingHash = user.getPassword();
        updater().updatePassword(stored.email(), passwordEncoder.encode(request.getPassword()));
        if (properties.isPasswordPolicyEnabled()) {
            passwordHistoryStore.record(stored.email(), outgoingHash, properties.getPasswordHistoryCount());
        }
        refreshTokenService.deleteByUserId(user.getId());

        eventPublisher.publishEvent(new PasswordResetEvent(stored.email()));

        return new MessageResponse("Password has been reset successfully.");
    }

    /**
     * Anti-réutilisation : refuse si le mot de passe brut correspond au hash courant
     * du compte ou à l'un des {@code password-history-count} précédents (bcrypt ne permet
     * pas de comparer hash à hash — on rejoue {@link PasswordEncoder#matches} sur chacun).
     *
     * @throws WeakPasswordException si le mot de passe figure dans l'historique
     */
    private void requireNotReused(String email, String rawPassword, String currentHash) {
        if (passwordEncoder.matches(rawPassword, currentHash)) {
            throw new WeakPasswordException(
                    "Password was recently used: choose a password you have not used before.");
        }
        for (String previousHash : passwordHistoryStore.find(email)) {
            if (passwordEncoder.matches(rawPassword, previousHash)) {
                throw new WeakPasswordException(
                        "Password was recently used: choose a password you have not used before.");
            }
        }
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
                    "Password reset is not enabled: set zrouga.security.reset-enabled=true "
                            + "(and configure reset-base-url, spring.mail.*, and AuthUserPasswordUpdater).");
        }
    }

    private InvalidResetTokenException invalidToken() {
        return new InvalidResetTokenException("Invalid or expired reset token.");
    }

    private AuthUserProvider provider() {
        return AuthSupport.provider(userProvider);
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
}
