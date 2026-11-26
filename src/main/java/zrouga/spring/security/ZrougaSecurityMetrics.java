package zrouga.spring.security;

import zrouga.spring.security.event.EmailVerifiedEvent;
import zrouga.spring.security.event.LockoutEvent;
import zrouga.spring.security.event.PasswordResetEvent;
import zrouga.spring.security.event.SignInEvent;
import zrouga.spring.security.event.SignInFailedEvent;
import zrouga.spring.security.event.SignOutEvent;
import zrouga.spring.security.event.SignUpEvent;
import zrouga.spring.security.event.TokenRefreshedEvent;

import org.springframework.context.event.EventListener;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * Métriques d'authentification (Micrometer) — enregistrement automatique des
 * événements du starter sur le {@link MeterRegistry} de l'application.
 *
 * <p>Disponible uniquement si {@code spring-boot-starter-actuator} (ou
 * {@code micrometer-core}) est sur le classpath ; sinon l'auto-config saute et
 * les événements sont simplement non écoutés.</p>
 *
 * <p>Mesures :</p>
 * <ul>
 * <li>{@code zrouga.security.signin} (tag {@code outcome=success|failure})</li>
 * <li>{@code zrouga.security.signup}, {@code zrouga.security.signout}</li>
 * <li>{@code zrouga.security.token.refresh}</li>
 * <li>{@code zrouga.security.account.lockout}</li>
 * <li>{@code zrouga.security.password.reset}, {@code zrouga.security.email.verified}</li>
 * </ul>
 */
public class ZrougaSecurityMetrics {

    public static final String SIGNIN = "zrouga.security.signin";

    public static final String SIGNUP = "zrouga.security.signup";

    public static final String SIGNOUT = "zrouga.security.signout";

    public static final String TOKEN_REFRESH = "zrouga.security.token.refresh";

    public static final String ACCOUNT_LOCKOUT = "zrouga.security.account.lockout";

    public static final String PASSWORD_RESET = "zrouga.security.password.reset";

    public static final String EMAIL_VERIFIED = "zrouga.security.email.verified";

    private final MeterRegistry registry;

    public ZrougaSecurityMetrics(MeterRegistry registry) {
        this.registry = registry;
    }

    @EventListener
    public void onSignIn(SignInEvent event) {
        count(SIGNIN, "outcome", "success");
    }

    @EventListener
    public void onSignInFailed(SignInFailedEvent event) {
        count(SIGNIN, "outcome", "failure");
    }

    @EventListener
    public void onSignUp(SignUpEvent event) {
        count(SIGNUP);
    }

    @EventListener
    public void onSignOut(SignOutEvent event) {
        count(SIGNOUT);
    }

    @EventListener
    public void onTokenRefreshed(TokenRefreshedEvent event) {
        count(TOKEN_REFRESH);
    }

    @EventListener
    public void onLockout(LockoutEvent event) {
        count(ACCOUNT_LOCKOUT);
    }

    @EventListener
    public void onPasswordReset(PasswordResetEvent event) {
        count(PASSWORD_RESET);
    }

    @EventListener
    public void onEmailVerified(EmailVerifiedEvent event) {
        count(EMAIL_VERIFIED);
    }

    private void count(String name, String... tags) {
        Counter.builder(name).tags(tags).register(registry).increment();
    }
}
