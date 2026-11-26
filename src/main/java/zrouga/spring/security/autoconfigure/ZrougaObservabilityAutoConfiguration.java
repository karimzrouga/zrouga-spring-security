package zrouga.spring.security.autoconfigure;

import zrouga.spring.security.ZrougaSecurityHealthIndicator;
import zrouga.spring.security.ZrougaSecurityMetrics;
import zrouga.spring.security.ZrougaSecurityProperties;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import io.micrometer.core.instrument.MeterRegistry;

/**
 * Observabilité (optionnelle) : métriques Micrometer et indicateur de santé —
 * active uniquement si {@code spring-boot-starter-actuator} est sur le
 * classpath (dépendance {@code optional} du starter).
 *
 * <ul>
 * <li>{@link ZrougaSecurityMetrics} : compteurs des événements d'auth sur le
 *     {@link MeterRegistry} de l'application ;</li>
 * <li>{@link ZrougaSecurityHealthIndicator} : résumé de la configuration sur
 *     {@code /actuator/health} (composant {@code zrougaSecurity}).</li>
 * </ul>
 */
@AutoConfiguration(afterName = "org.springframework.boot.micrometer.metrics.autoconfigure."
        + "CompositeMeterRegistryAutoConfiguration")
@ConditionalOnClass(name = { "io.micrometer.core.instrument.MeterRegistry",
        "org.springframework.boot.health.contributor.HealthIndicator" })
@EnableConfigurationProperties(ZrougaSecurityProperties.class)
public class ZrougaObservabilityAutoConfiguration {

    @Bean
    @ConditionalOnBean(MeterRegistry.class)
    @ConditionalOnMissingBean(ZrougaSecurityMetrics.class)
    public ZrougaSecurityMetrics zrougaSecurityMetrics(MeterRegistry registry) {
        return new ZrougaSecurityMetrics(registry);
    }

    @Bean
    @ConditionalOnMissingBean(ZrougaSecurityHealthIndicator.class)
    public ZrougaSecurityHealthIndicator zrougaSecurityHealthIndicator(ZrougaSecurityProperties properties) {
        return new ZrougaSecurityHealthIndicator(properties);
    }
}
