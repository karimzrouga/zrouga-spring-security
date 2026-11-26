package zrouga.spring.security;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

import zrouga.spring.security.event.EmailVerifiedEvent;
import zrouga.spring.security.event.SignUpEvent;
import zrouga.spring.security.exception.EmailVerificationNotSupportedException;
import zrouga.spring.security.exception.InvalidEmailVerificationTokenException;
import zrouga.spring.security.payload.MessageResponse;
import zrouga.spring.security.payload.ResendVerificationRequest;
import zrouga.spring.security.payload.VerifyEmailRequest;
import zrouga.spring.security.ratelimit.LoginRateLimiter;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;

/**
 * Vérification de l'e-mail à l'inscription — fonctionnalité <b>optionnelle</b>,
 * active uniquement si {@code zrouga.security.email-verification-enabled=true}.
 *
 * <p>Flux : après {@code /signup} ({@link SignUpEvent}), un jeton usage unique
 * (24 h par défaut) part par e-mail ; {@code /verify-email} le consomme
 * <b>avant</b> l'appel à {@link AuthUserEmailVerifier} (claim first) puis publie
 * {@link EmailVerifiedEvent} ; {@code /resend-verification} renvoie un jeton neuf
 * avec le même message que pour un compte inexistant (anti-énumération).</p>
 *
 * <p>L'état « e-mail vérifié » reste côté application (votre table utilisateur) :
 * le starter ne fait que délivrer et consommer les jetons. Le démarrage échoue
 * sans {@code AuthUserEmailVerifier}, {@code email-verification-base-url} ni
 * expéditeur d'e-mail.</p>
 */
public class EmailVerificationService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final ZrougaSecurityProperties properties;
    private final ObjectProvider<AuthUserProvider> userProvider;
    private final ObjectProvider<AuthUserEmailVerifier> emailVerifier;
    private final ObjectProvider<EmailVerificationEmailSender> emailSender;
    private final EmailVerificationTokenStore tokenStore;
    private final LoginRateLimiter rateLimiter;
    private final ApplicationEventPublisher eventPublisher;

    public EmailVerificationService(
            ZrougaSecurityProperties properties,
            ObjectProvider<AuthUserProvider> userProvider,
            ObjectProvider<AuthUserEmailVerifier> emailVerifier,
            ObjectProvider<EmailVerificationEmailSender> emailSender,
            EmailVerificationTokenStore tokenStore,
            LoginRateLimiter rateLimiter,
            ApplicationEventPublisher eventPublisher) {
        this.properties = properties;
        this.userProvider = userProvider;
        this.emailVerifier = emailVerifier;
        this.emailSender = emailSender;
        this.tokenStore = tokenStore;
        this.rateLimiter = rateLimiter;
        this.eventPublisher = eventPublisher;
        validateWhenEnabled();
    }

    /** Envoi automatique à l'inscription (silencieux si la fonctionnalité est désactivée). */
    @EventListener
    public void onSignUp(SignUpEvent event) {
        if (!properties.isEmailVerificationEnabled()) {
            return;
        }
        issueToken(event.email());
    }

    /**
     * Renvoie un jeton de vérification neuf — toujours le même message, que le
     * compte existe ou non (anti-énumération), rate-limité par e-mail et par IP.
     *
     * @param request  la demande
     * @param clientIp IP du client (rate-limit)
     */
    public MessageResponse resendVerification(ResendVerificationRequest request, String clientIp) {
        requireEnabled();

        String email = request.email();
        rateLimiter.check("verification:email:" + AuthSupport.rateLimitKey(email));
        rateLimiter.checkIp("verification:ip:" + clientIp);

        if (provider().findByEmail(email).isPresent()) {
            issueToken(email);
        }

        return new MessageResponse("If the account exists, a verification email has been sent.");
    }

    /**
     * Consomme le jeton et marque l'e-mail comme vérifié (usage unique, 24 h).
     *
     * @param request  la demande
     * @param clientIp IP du client (rate-limit anti-force brute du jeton)
     */
    public MessageResponse verify(VerifyEmailRequest request, String clientIp) {
        requireEnabled();

        rateLimiter.checkIp("verification:token:ip:" + clientIp);

        String rawToken = request.token();
        StoredEmailVerificationToken stored = tokenStore.findByToken(rawToken)
                .filter(token -> token.expiry().isAfter(Instant.now()))
                .orElseThrow(() -> new InvalidEmailVerificationTokenException(
                        "Invalid or expired verification token."));

        // Compte supprimé entre-temps : jeton invalide, rien n'est consommé.
        if (provider().findByEmail(stored.email()).isEmpty()) {
            throw new InvalidEmailVerificationTokenException("Invalid or expired verification token.");
        }

        // Claim first : un seul concurrent peut consommer le jeton.
        if (!tokenStore.consume(rawToken)) {
            throw new InvalidEmailVerificationTokenException("Invalid or expired verification token.");
        }

        verifier().verifyEmail(stored.email());
        rateLimiter.reset("verification:token:ip:" + clientIp);
        eventPublisher.publishEvent(new EmailVerifiedEvent(stored.email()));

        return new MessageResponse("Email verified successfully.");
    }

    private void issueToken(String email) {
        tokenStore.deleteByEmail(email);
        String rawToken = generateToken();
        Instant expiry = Instant.now().plusMillis(properties.getEmailVerificationTokenTtlMs());
        tokenStore.save(new StoredEmailVerificationToken(rawToken, email, expiry));
        sender().send(email, rawToken);
    }

    private void validateWhenEnabled() {
        if (!properties.isEmailVerificationEnabled()) {
            return;
        }
        if (properties.getEmailVerificationBaseUrl() == null || properties.getEmailVerificationBaseUrl().isBlank()) {
            throw new IllegalStateException(
                    "zrouga.security.email-verification-enabled=true : "
                            + "zrouga.security.email-verification-base-url est obligatoire "
                            + "(URL de la page de vérification côté front).");
        }
        if (emailVerifier.getIfAvailable() == null) {
            throw new IllegalStateException(AuthUserEmailVerifier.MISSING_BEAN_MESSAGE);
        }
        if (emailSender.getIfAvailable() == null) {
            throw new IllegalStateException(
                    "zrouga.security.email-verification-enabled=true : aucun bean "
                            + "EmailVerificationEmailSender disponible.");
        }
    }

    private void requireEnabled() {
        if (!properties.isEmailVerificationEnabled()) {
            throw new EmailVerificationNotSupportedException(
                    "Email verification is not enabled: set zrouga.security.email-verification-enabled=true "
                            + "(and configure email-verification-base-url, spring.mail.*, and "
                            + "AuthUserEmailVerifier).");
        }
    }

    private AuthUserProvider provider() {
        return AuthSupport.provider(userProvider);
    }

    private AuthUserEmailVerifier verifier() {
        AuthUserEmailVerifier verifier = emailVerifier.getIfAvailable();
        if (verifier == null) {
            throw new IllegalStateException(AuthUserEmailVerifier.MISSING_BEAN_MESSAGE);
        }
        return verifier;
    }

    private EmailVerificationEmailSender sender() {
        EmailVerificationEmailSender sender = emailSender.getIfAvailable();
        if (sender == null) {
            throw new IllegalStateException(
                    "zrouga.security.email-verification-enabled=true : aucun bean "
                            + "EmailVerificationEmailSender disponible.");
        }
        return sender;
    }

    private static String generateToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
