package zrouga.spring.security.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Optional;

import zrouga.spring.security.AuthResource;
import zrouga.spring.security.AuthService;
import zrouga.spring.security.AuthUser;
import zrouga.spring.security.AuthUserPasswordUpdater;
import zrouga.spring.security.AuthUserProvider;
import zrouga.spring.security.InMemoryRefreshTokenStore;
import zrouga.spring.security.PasswordResetEmailSender;
import zrouga.spring.security.PasswordResetService;
import zrouga.spring.security.RefreshTokenService;
import zrouga.spring.security.RefreshTokenStore;
import zrouga.spring.security.TestSecret;
import zrouga.spring.security.UserDetailsImpl;
import zrouga.spring.security.UserDetailsServiceImpl;
import zrouga.spring.security.ZrougaSecurityProperties;
import zrouga.spring.security.autoconfigure.ZrougaCleanupAutoConfiguration;
import zrouga.spring.security.autoconfigure.ZrougaInMemoryRefreshTokenAutoConfiguration;
import zrouga.spring.security.autoconfigure.ZrougaJpaRefreshTokenAutoConfiguration;
import zrouga.spring.security.autoconfigure.ZrougaSecurityAutoConfiguration;
import zrouga.spring.security.exception.PasswordResetNotSupportedException;
import zrouga.spring.security.exception.SignupNotSupportedException;
import zrouga.spring.security.exception.TokenControllerAdvice;
import zrouga.spring.security.jpa.JpaRefreshTokenStore;
import zrouga.spring.security.jwt.AuthEntryPointJwt;
import zrouga.spring.security.jwt.AuthTokenFilter;
import zrouga.spring.security.jwt.JwtUtils;
import zrouga.spring.security.payload.ForgotPasswordRequest;
import zrouga.spring.security.payload.SignupRequest;
import zrouga.spring.security.ratelimit.InMemoryLoginRateLimiter;
import zrouga.spring.security.ratelimit.LoginRateLimiter;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Conditions de repli (backoff) des auto-configs : beans surchargeables,
 * branche en mémoire sans JPA, échec explicite sans AuthUserProvider.
 */
class AutoConfigurationBackoffTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    ZrougaSecurityAutoConfiguration.class,
                    ZrougaJpaRefreshTokenAutoConfiguration.class,
                    ZrougaInMemoryRefreshTokenAutoConfiguration.class,
                    ZrougaCleanupAutoConfiguration.class))
            .withPropertyValues("zrouga.security.jwt-secret=" + TestSecret.SECRET);

    @Test
    void beansParDefautPresents() {
        runner.withUserConfiguration(ProviderConfiguration.class).run(context -> {
            assertThat(context).hasSingleBean(JwtUtils.class);
            assertThat(context).hasSingleBean(AuthTokenFilter.class);
            assertThat(context).hasSingleBean(AuthService.class);
            assertThat(context).hasSingleBean(AuthResource.class);
            assertThat(context).hasSingleBean(TokenControllerAdvice.class);
            assertThat(context).hasSingleBean(AuthEntryPointJwt.class);
            assertThat(context).hasSingleBean(UserDetailsServiceImpl.class);
            assertThat(context).hasSingleBean(AuthenticationManager.class);
            assertThat(context).hasSingleBean(SecurityFilterChain.class);
            assertThat(context).hasSingleBean(PasswordEncoder.class);
            assertThat(context).hasSingleBean(LoginRateLimiter.class);
            assertThat(context).hasSingleBean(RefreshTokenService.class);
            assertThat(context.getBean(PasswordEncoder.class)).isInstanceOf(BCryptPasswordEncoder.class);
            assertThat(context.getBean(LoginRateLimiter.class)).isInstanceOf(InMemoryLoginRateLimiter.class);
        });
    }

    @Test
    void brancheEnMemoireSansEntityManagerFactory() {
        runner.withUserConfiguration(ProviderConfiguration.class).run(context -> {
            assertThat(context).hasSingleBean(RefreshTokenStore.class);
            assertThat(context.getBean(RefreshTokenStore.class)).isInstanceOf(InMemoryRefreshTokenStore.class);
            assertThat(context).doesNotHaveBean(JpaRefreshTokenStore.class);
        });
    }

    @Test
    void echecExpliciteSansAuthUserProvider() {
        runner.run(context -> {
            Throwable failure = context.getStartupFailure();
            assertThat(failure).isNotNull();
            assertThat(messages(failure)).contains("AuthUserProvider");
        });
    }

    @Test
    void signupSansCreateurRenvoieSignupNotSupported() {
        runner.withUserConfiguration(ProviderConfiguration.class).run(context -> {
            SignupRequest request = new SignupRequest();
            request.setEmail("nouveau@test.com");
            request.setPassword("MotDePasse123");

            assertThatThrownBy(() -> context.getBean(AuthService.class).signup(request))
                    .isInstanceOf(SignupNotSupportedException.class)
                    .hasMessageContaining("AuthUserCreator");
        });
    }

    @Test
    void resetPasswordDesactiveRenvoie501() {
        runner.withUserConfiguration(ProviderConfiguration.class).run(context -> {
            ForgotPasswordRequest request = new ForgotPasswordRequest();
            request.setEmail("nouveau@test.com");

            assertThatThrownBy(() -> context.getBean(PasswordResetService.class).forgotPassword(request))
                    .isInstanceOf(PasswordResetNotSupportedException.class)
                    .hasMessageContaining("reset-enabled");
        });
    }

    @Test
    void resetEnabledSansUpdatourEchoueAuDemarrage() {
        runner.withUserConfiguration(ProviderConfiguration.class, ResetSenderConfiguration.class)
                .withPropertyValues(
                        "zrouga.security.reset-enabled=true",
                        "zrouga.security.reset-base-url=https://front.test/reset")
                .run(context -> {
                    Throwable failure = context.getStartupFailure();
                    assertThat(failure).isNotNull();
                    assertThat(messages(failure)).contains("AuthUserPasswordUpdater");
                });
    }

    @Test
    void resetEnabledSansSmtpEchoueAuDemarrage() {
        runner.withUserConfiguration(ProviderConfiguration.class, ResetUpdaterConfiguration.class)
                .withPropertyValues(
                        "zrouga.security.reset-enabled=true",
                        "zrouga.security.reset-base-url=https://front.test/reset")
                .run(context -> {
                    Throwable failure = context.getStartupFailure();
                    assertThat(failure).isNotNull();
                    assertThat(messages(failure)).contains("JavaMailSender");
                });
    }

    @Test
    void beansUtilisateurRemplacentLesBecsDuStarter() {
        runner.withUserConfiguration(ProviderConfiguration.class, CustomBeansConfiguration.class).run(context -> {
            assertThat(context.getBean(PasswordEncoder.class))
                    .isSameAs(context.getBean("customPasswordEncoder"));
            assertThat(context.getBean(JwtUtils.class)).isSameAs(context.getBean("customJwtUtils"));
            assertThat(context.getBean(AuthTokenFilter.class)).isSameAs(context.getBean("customAuthTokenFilter"));
            assertThat(context.getBean(UserDetailsService.class))
                    .isSameAs(context.getBean("customUserDetailsService"));
            assertThat(context).doesNotHaveBean(UserDetailsServiceImpl.class);
            assertThat(context.getBean(AuthenticationManager.class))
                    .isSameAs(context.getBean("customAuthenticationManager"));
            assertThat(context).hasSingleBean(AuthenticationProvider.class);
            assertThat(context).doesNotHaveBean(DaoAuthenticationProvider.class);
            assertThat(context.getBean(RefreshTokenStore.class))
                    .isSameAs(context.getBean("customRefreshTokenStore"));
            assertThat(context).doesNotHaveBean(JpaRefreshTokenStore.class);
            assertThat(context.getBean(LoginRateLimiter.class)).isSameAs(context.getBean("customLoginRateLimiter"));
            assertThat(context.getBean(SecurityFilterChain.class)).isSameAs(context.getBean("customFilterChain"));
            assertThat(context.getBean(RefreshTokenService.class))
                    .isSameAs(context.getBean("customRefreshTokenService"));
            assertThat(context.getBean(AuthService.class)).isSameAs(context.getBean("customAuthService"));
            assertThat(context.getBean(AuthResource.class)).isSameAs(context.getBean("customAuthResource"));
            assertThat(context.getBean(AuthEntryPointJwt.class))
                    .isSameAs(context.getBean("customAuthEntryPointJwt"));
            assertThat(context.getBean(TokenControllerAdvice.class))
                    .isSameAs(context.getBean("customTokenControllerAdvice"));
        });
    }

    private static String messages(Throwable failure) {
        StringBuilder sb = new StringBuilder();
        Throwable current = failure;
        while (current != null) {
            sb.append(current.getMessage()).append('\n');
            current = current.getCause();
        }
        return sb.toString();
    }

    @Configuration(proxyBeanMethods = false)
    static class ProviderConfiguration {

        @Bean
        AuthUserProvider authUserProvider() {
            return new AuthUserProvider() {
                @Override
                public Optional<AuthUser> findByEmail(String email) {
                    return Optional.empty();
                }

                @Override
                public Optional<AuthUser> findById(Long id) {
                    return Optional.empty();
                }
            };
        }

        @Bean
        org.springframework.web.cors.CorsConfigurationSource corsConfigurationSource() {
            return new org.springframework.web.cors.UrlBasedCorsConfigurationSource();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class ResetSenderConfiguration {

        @Bean
        PasswordResetEmailSender passwordResetEmailSender() {
            return (email, rawToken) -> {
            };
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class ResetUpdaterConfiguration {

        @Bean
        AuthUserPasswordUpdater authUserPasswordUpdater() {
            return (email, encodedPassword) -> {
            };
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomBeansConfiguration {

        @Bean
        PasswordEncoder customPasswordEncoder() {
            return new BCryptPasswordEncoder(4);
        }

        @Bean
        JwtUtils customJwtUtils(ZrougaSecurityProperties properties) {
            return new JwtUtils(properties);
        }

        @Bean
        AuthTokenFilter customAuthTokenFilter(JwtUtils jwtUtils) {
            return new AuthTokenFilter(jwtUtils);
        }

        @Bean
        UserDetailsService customUserDetailsService() {
            return username -> {
                throw new UsernameNotFoundException("custom");
            };
        }

        @Bean
        AuthenticationProvider customAuthenticationProvider() {
            return new AuthenticationProvider() {
                @Override
                public Authentication authenticate(Authentication authentication) {
                    return null;
                }

                @Override
                public boolean supports(Class<?> authentication) {
                    return true;
                }
            };
        }

        @Bean
        AuthenticationManager customAuthenticationManager() {
            return authentication -> authentication;
        }

        @Bean
        RefreshTokenStore customRefreshTokenStore() {
            return new InMemoryRefreshTokenStore();
        }

        @Bean
        LoginRateLimiter customLoginRateLimiter() {
            return new LoginRateLimiter() {
                @Override
                public void check(String key) {
                }

                @Override
                public void recordFailure(String key) {
                }

                @Override
                public void reset(String key) {
                }
            };
        }

        @Bean
        SecurityFilterChain customFilterChain(HttpSecurity http) throws Exception {
            http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                    .csrf(AbstractHttpConfigurer::disable);
            return http.build();
        }

        @Bean
        RefreshTokenService customRefreshTokenService(RefreshTokenStore store, ZrougaSecurityProperties properties) {
            return new RefreshTokenService(store, properties);
        }

        @Bean
        AuthService customAuthService(
                AuthenticationManager authenticationManager,
                org.springframework.beans.factory.ObjectProvider<AuthUserProvider> userProvider,
                JwtUtils jwtUtils,
                RefreshTokenService refreshTokenService,
                LoginRateLimiter loginRateLimiter,
                PasswordEncoder passwordEncoder,
                org.springframework.beans.factory.ObjectProvider<zrouga.spring.security.AuthUserCreator> creatorProvider) {
            return new AuthService(authenticationManager, userProvider, jwtUtils, refreshTokenService,
                    loginRateLimiter, passwordEncoder, creatorProvider);
        }

        @Bean
        AuthResource customAuthResource(AuthService authService, PasswordResetService passwordResetService) {
            return new AuthResource(authService, passwordResetService);
        }

        @Bean
        AuthEntryPointJwt customAuthEntryPointJwt() {
            return new AuthEntryPointJwt();
        }

        @Bean
        TokenControllerAdvice customTokenControllerAdvice() {
            return new TokenControllerAdvice();
        }
    }
}
