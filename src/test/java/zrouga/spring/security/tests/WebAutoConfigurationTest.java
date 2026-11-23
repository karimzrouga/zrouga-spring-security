package zrouga.spring.security.tests;

import static org.assertj.core.api.Assertions.assertThat;

import zrouga.spring.security.AuthResource;
import zrouga.spring.security.AuthService;
import zrouga.spring.security.TestSecret;
import zrouga.spring.security.UserDetailsServiceImpl;
import zrouga.spring.security.autoconfigure.ZrougaCleanupAutoConfiguration;
import zrouga.spring.security.autoconfigure.ZrougaInMemoryRefreshTokenAutoConfiguration;
import zrouga.spring.security.autoconfigure.ZrougaJpaRefreshTokenAutoConfiguration;
import zrouga.spring.security.autoconfigure.ZrougaSecurityAutoConfiguration;
import zrouga.spring.security.exception.TokenControllerAdvice;
import zrouga.spring.security.jwt.AuthEntryPointJwt;
import zrouga.spring.security.jwt.AuthTokenFilter;
import zrouga.spring.security.jwt.JwtUtils;
import zrouga.spring.security.ratelimit.InMemoryLoginRateLimiter;
import zrouga.spring.security.ratelimit.LoginRateLimiter;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * L'auto-config s'amorce aussi dans un contexte web servlet
 * (spring-boot-starter-web est optionnel dans le starter).
 */
class WebAutoConfigurationTest {

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    ZrougaSecurityAutoConfiguration.class,
                    ZrougaJpaRefreshTokenAutoConfiguration.class,
                    ZrougaInMemoryRefreshTokenAutoConfiguration.class,
                    ZrougaCleanupAutoConfiguration.class))
            .withPropertyValues("zrouga.security.jwt-secret=" + TestSecret.SECRET);

    @Test
    void autoConfigureDansUnContexteWeb() {
        runner.withUserConfiguration(AutoConfigurationBackoffTest.ProviderConfiguration.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(SecurityFilterChain.class);
            assertThat(context).hasSingleBean(JwtUtils.class);
            assertThat(context).hasSingleBean(AuthTokenFilter.class);
            assertThat(context).hasSingleBean(AuthService.class);
            assertThat(context).hasSingleBean(AuthResource.class);
            assertThat(context).hasSingleBean(TokenControllerAdvice.class);
            assertThat(context).hasSingleBean(AuthEntryPointJwt.class);
            assertThat(context).hasSingleBean(UserDetailsServiceImpl.class);
            assertThat(context).hasSingleBean(AuthenticationManager.class);
            assertThat(context).hasSingleBean(LoginRateLimiter.class);
            assertThat(context).hasSingleBean(InMemoryLoginRateLimiter.class);
        });
    }
}
