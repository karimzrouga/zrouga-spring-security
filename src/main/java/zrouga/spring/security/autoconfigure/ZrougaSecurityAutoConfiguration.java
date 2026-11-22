package zrouga.spring.security.autoconfigure;

import zrouga.spring.security.AuthResource;
import zrouga.spring.security.AuthService;
import zrouga.spring.security.AuthUserProvider;
import zrouga.spring.security.RefreshTokenService;
import zrouga.spring.security.RefreshTokenStore;
import zrouga.spring.security.UserDetailsServiceImpl;
import zrouga.spring.security.ZrougaSecurityProperties;
import zrouga.spring.security.exception.TokenControllerAdvice;
import zrouga.spring.security.jwt.AuthEntryPointJwt;
import zrouga.spring.security.jwt.AuthTokenFilter;
import zrouga.spring.security.jwt.JwtUtils;
import zrouga.spring.security.ratelimit.InMemoryLoginRateLimiter;
import zrouga.spring.security.ratelimit.LoginRateLimiter;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Configuration auto-activée du starter : sécurité stateless JWT, endpoints d'authentification
 * et tous les beans de base. Chaque bean est surchargeable — déclarez le vôtre et celui du
 * starter est remplacé.
 */
@AutoConfiguration(before = { ServletWebSecurityAutoConfiguration.class,
        UserDetailsServiceAutoConfiguration.class })
@EnableWebSecurity
@EnableMethodSecurity
@EnableConfigurationProperties(ZrougaSecurityProperties.class)
public class ZrougaSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(PasswordEncoder.class)
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @ConditionalOnMissingBean(AuthEntryPointJwt.class)
    public AuthEntryPointJwt authEntryPointJwt() {
        return new AuthEntryPointJwt();
    }

    @Bean
    @ConditionalOnMissingBean(AuthTokenFilter.class)
    public AuthTokenFilter authenticationJwtTokenFilter(JwtUtils jwtUtils) {
        return new AuthTokenFilter(jwtUtils);
    }

    @Bean
    @ConditionalOnMissingBean(AuthenticationProvider.class)
    public DaoAuthenticationProvider authenticationProvider(
            PasswordEncoder passwordEncoder,
            UserDetailsService userDetailsService) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    @ConditionalOnMissingBean(AuthenticationManager.class)
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    @ConditionalOnMissingBean(JwtUtils.class)
    public JwtUtils jwtUtils(ZrougaSecurityProperties properties) {
        return new JwtUtils(properties);
    }

    @Bean
    @ConditionalOnMissingBean(UserDetailsService.class)
    public UserDetailsServiceImpl userDetailsService(ObjectProvider<AuthUserProvider> userProvider) {
        return new UserDetailsServiceImpl(userProvider);
    }

    @Bean
    @ConditionalOnMissingBean(RefreshTokenService.class)
    public RefreshTokenService refreshTokenService(
            RefreshTokenStore refreshTokenStore,
            ZrougaSecurityProperties properties) {
        return new RefreshTokenService(refreshTokenStore, properties);
    }

    @Bean
    @ConditionalOnMissingBean(LoginRateLimiter.class)
    public LoginRateLimiter loginRateLimiter(ZrougaSecurityProperties properties) {
        return new InMemoryLoginRateLimiter(properties);
    }

    @Bean
    @ConditionalOnMissingBean(AuthService.class)
    public AuthService authService(
            AuthenticationManager authenticationManager,
            ObjectProvider<AuthUserProvider> userProvider,
            JwtUtils jwtUtils,
            RefreshTokenService refreshTokenService,
            LoginRateLimiter loginRateLimiter) {
        return new AuthService(authenticationManager, userProvider, jwtUtils, refreshTokenService,
                loginRateLimiter);
    }

    @Bean
    @ConditionalOnMissingBean(AuthResource.class)
    public AuthResource authResource(AuthService authService) {
        return new AuthResource(authService);
    }

    @Bean
    @ConditionalOnMissingBean(TokenControllerAdvice.class)
    public TokenControllerAdvice tokenControllerAdvice() {
        return new TokenControllerAdvice();
    }

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            AuthenticationProvider authenticationProvider,
            AuthTokenFilter authenticationJwtTokenFilter,
            AuthEntryPointJwt unauthorizedHandler,
            ZrougaSecurityProperties properties) throws Exception {

        http
                .cors(Customizer.withDefaults())

                .csrf(AbstractHttpConfigurer::disable)

                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(unauthorizedHandler))

                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(properties.getPublicPaths().toArray(String[]::new)).permitAll()
                        .anyRequest().authenticated())

                .authenticationProvider(authenticationProvider)

                .addFilterBefore(
                        authenticationJwtTokenFilter,
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public InitializingBean zrougaAuthUserProviderRequired(ObjectProvider<AuthUserProvider> provider) {
        return () -> {
            if (provider.getIfAvailable() == null) {
                throw new IllegalStateException(AuthUserProvider.MISSING_BEAN_MESSAGE);
            }
        };
    }
}
