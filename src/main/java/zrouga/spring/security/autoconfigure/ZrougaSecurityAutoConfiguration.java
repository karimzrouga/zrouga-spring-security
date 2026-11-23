package zrouga.spring.security.autoconfigure;

import zrouga.spring.security.AuthResource;
import zrouga.spring.security.AuthService;
import zrouga.spring.security.AuthUserCreator;
import zrouga.spring.security.AuthUserPasswordUpdater;
import zrouga.spring.security.AuthUserProvider;
import zrouga.spring.security.InMemoryPasswordResetTokenStore;
import zrouga.spring.security.PasswordResetEmailSender;
import zrouga.spring.security.PasswordResetService;
import zrouga.spring.security.PasswordResetTokenStore;
import zrouga.spring.security.RefreshTokenService;
import zrouga.spring.security.RefreshTokenStore;
import zrouga.spring.security.SmtpPasswordResetEmailSender;
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
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.task.TaskExecutor;
import org.springframework.mail.javamail.JavaMailSender;
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
import org.springframework.web.cors.CorsConfigurationSource;

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
            LoginRateLimiter loginRateLimiter,
            PasswordEncoder passwordEncoder,
            ObjectProvider<AuthUserCreator> creatorProvider) {
        return new AuthService(authenticationManager, userProvider, jwtUtils, refreshTokenService,
                loginRateLimiter, passwordEncoder, creatorProvider);
    }

    @Bean
    @ConditionalOnMissingBean(AuthResource.class)
    public AuthResource authResource(AuthService authService, PasswordResetService passwordResetService,
            ZrougaSecurityProperties properties) {
        return new AuthResource(authService, passwordResetService, properties);
    }

    @Bean
    @ConditionalOnMissingBean(PasswordResetTokenStore.class)
    public PasswordResetTokenStore passwordResetTokenStore() {
        return new InMemoryPasswordResetTokenStore();
    }

    @Bean
    @ConditionalOnMissingBean(PasswordResetEmailSender.class)
    @ConditionalOnProperty(prefix = "zrouga.security", name = "reset-enabled", havingValue = "true")
    public SmtpPasswordResetEmailSender smtpPasswordResetEmailSender(
            ObjectProvider<JavaMailSender> mailSender,
            ZrougaSecurityProperties properties,
            ObjectProvider<TaskExecutor> taskExecutor) {
        return new SmtpPasswordResetEmailSender(mailSender, properties, taskExecutor);
    }

    @Bean
    @ConditionalOnMissingBean(PasswordResetService.class)
    public PasswordResetService passwordResetService(
            ZrougaSecurityProperties properties,
            ObjectProvider<AuthUserProvider> userProvider,
            ObjectProvider<AuthUserPasswordUpdater> passwordUpdater,
            ObjectProvider<PasswordResetEmailSender> emailSender,
            PasswordResetTokenStore passwordResetTokenStore,
            RefreshTokenService refreshTokenService,
            LoginRateLimiter loginRateLimiter,
            PasswordEncoder passwordEncoder) {
        return new PasswordResetService(properties, userProvider, passwordUpdater, emailSender,
                passwordResetTokenStore, refreshTokenService, loginRateLimiter, passwordEncoder);
    }

    @Bean
    @ConditionalOnMissingBean(TokenControllerAdvice.class)
    public TokenControllerAdvice tokenControllerAdvice() {
        return new TokenControllerAdvice();
    }

    /**
     * Chaîne de filtres par défaut : tout est authentifié sauf les chemins publics
     * ({@code zrouga.security.public-paths}, qui couvrent par défaut {@code /api/auth/**}
     * — donc aussi {@code POST /api/auth/signup}).
     *
     * <p><b>Autorisation par rôle d'une API non publique</b> (2 approches) :</p>
     * <ul>
     * <li><b>Sur un contrôleur / méthode</b> — {@code @EnableMethodSecurity} est déjà actif :
     * <pre>{@code
     * @PreAuthorize("hasRole('ADMIN')")
     * @GetMapping("/api/admin/stats")
     * public Stats stats() { ... }
     *
     * @PreAuthorize("hasAnyRole('ADMIN', 'AQP')")
     * @GetMapping("/api/controle/rapports")
     * public List<Rapport> rapports() { ... }
     * }</pre></li>
     * <li><b>Dans un SecurityFilterChain surchargeable</b> (déclarez votre propre bean
     * {@code SecurityFilterChain} — celui du starter est alors remplacé) :
     * <pre>{@code
     * @Bean
     * SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
     *     http.csrf(AbstractHttpConfigurer::disable)
     *         .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
     *         .authorizeHttpRequests(auth -> auth
     *             .requestMatchers("/api/auth/**").permitAll()      // public
     *             .requestMatchers("/api/admin/**").hasRole("ADMIN") // non public, rôle requis
     *             .requestMatchers("/api/controle/**").hasAnyRole("ADMIN", "AQP")
     *             .anyRequest().authenticated())                     // le reste : jeton valide
     *         .exceptionHandling(e -> e.authenticationEntryPoint(unauthorizedHandler));
     *     return http.build();
     * }
     * }</pre></li>
     * </ul>
     *
     * <p>Les rôles proviennent de {@link zrouga.spring.security.AuthUser#getRoles()} <b>sans</b> préfixe (ex :
     * {@code "ADMIN"}) ; le préfixe {@code ROLE_} est ajouté automatiquement à la construction
     * des autorités — écrivez donc {@code hasRole("ADMIN")}, jamais {@code hasRole("ROLE_ADMIN")}.
     * Sans préfixe ajouté, {@code hasRole} ne trouverait jamais le rôle et renverrait 403.</p>
     */
    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            AuthenticationProvider authenticationProvider,
            AuthTokenFilter authenticationJwtTokenFilter,
            AuthEntryPointJwt unauthorizedHandler,
            ZrougaSecurityProperties properties,
            ObjectProvider<CorsConfigurationSource> corsConfigurationSource) throws Exception {

        // CORS n'est activé que si l'application fournit sa propre source —
        // le starter n'impose aucune politique CORS.
        if (corsConfigurationSource.getIfAvailable() != null) {
            http.cors(Customizer.withDefaults());
        }

        http
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
