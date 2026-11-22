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

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
    public AuthEntryPointJwt authEntryPointJwt() {
        return new AuthEntryPointJwt();
    }

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter(
            JwtUtils jwtUtils,
            UserDetailsServiceImpl userDetailsService) {
        return new AuthTokenFilter(jwtUtils, userDetailsService);
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider(
            PasswordEncoder passwordEncoder,
            UserDetailsServiceImpl userDetailsService) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public JwtUtils jwtUtils(ZrougaSecurityProperties properties) {
        return new JwtUtils(properties);
    }

    @Bean
    public UserDetailsServiceImpl userDetailsService(AuthUserProvider userRepository) {
        return new UserDetailsServiceImpl(userRepository);
    }

    @Bean
    public RefreshTokenService refreshTokenService(
            RefreshTokenStore refreshTokenStore,
            ZrougaSecurityProperties properties) {
        return new RefreshTokenService(refreshTokenStore, properties);
    }

    @Bean
    public AuthService authService(
            AuthenticationManager authenticationManager,
            AuthUserProvider userRepository,
            JwtUtils jwtUtils,
            RefreshTokenService refreshTokenService) {
        return new AuthService(authenticationManager, userRepository, jwtUtils, refreshTokenService);
    }

    @Bean
    public AuthResource authResource(AuthService authService) {
        return new AuthResource(authService);
    }

    @Bean
    public TokenControllerAdvice tokenControllerAdvice() {
        return new TokenControllerAdvice();
    }

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            DaoAuthenticationProvider authenticationProvider,
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
                throw new IllegalStateException(
                        "zrouga.spring.security : aucun bean AuthUserProvider déclaré. "
                                + "Implémentez zrouga.spring.security.AuthUserProvider et déclarez-la comme @Component ou @Bean.");
            }
        };
    }
}
