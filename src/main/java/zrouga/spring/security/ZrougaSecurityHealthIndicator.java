package zrouga.spring.security;

import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.boot.health.contributor.Status;

/**
 * Santé de la configuration du starter — expose l'état des fonctionnalités
 * optionnelles sur {@code /actuator/health} (id de composant
 * {@code zrougaSecurity}).
 *
 * <p>Toujours {@code UP} : ce composant résume la <b>configuration</b> (et non
 * une dépendance externe) — les détails servent à vérifier en production quelles
 * options sont actives sans relire le YAML.</p>
 */
public class ZrougaSecurityHealthIndicator implements HealthIndicator {

    private final ZrougaSecurityProperties properties;

    public ZrougaSecurityHealthIndicator(ZrougaSecurityProperties properties) {
        this.properties = properties;
    }

    @Override
    public Health health() {
        return Health.up()
                .withDetail("authMode", properties.getAuthMode())
                .withDetail("revocation", properties.isRevocationEnabled())
                .withDetail("concurrentSessions", properties.isConcurrentSessionsEnabled())
                .withDetail("refreshBinding", properties.isRefreshBindingEnabled())
                .withDetail("emailVerification", properties.isEmailVerificationEnabled())
                .withDetail("twoFactor", properties.isTwoFactorEnabled())
                .withDetail("lockout", properties.isLockoutEnabled())
                .withDetail("passwordPolicy", properties.isPasswordPolicyEnabled())
                .withDetail("passwordReset", properties.isResetEnabled())
                .withDetail("signup", true)
                .withDetail("status", Status.UP.getCode())
                .build();
    }
}
