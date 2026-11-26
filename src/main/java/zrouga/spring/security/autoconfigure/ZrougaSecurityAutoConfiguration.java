package zrouga.spring.security.autoconfigure;

import zrouga.spring.security.AccountLockoutService;
import zrouga.spring.security.AccessTokenRevocation;
import zrouga.spring.security.AccessTokenRevocationStore;
import zrouga.spring.security.AuthResource;
import zrouga.spring.security.AuthService;
import zrouga.spring.security.AuthUserCreator;
import zrouga.spring.security.AuthUserEmailVerifier;
import zrouga.spring.security.AuthUserPasswordUpdater;
import zrouga.spring.security.AuthUserProvider;
import zrouga.spring.security.EmailVerificationEmailSender;
import zrouga.spring.security.EmailVerificationService;
import zrouga.spring.security.EmailVerificationTokenStore;
import zrouga.spring.security.InMemoryAccessTokenRevocationStore;
import zrouga.spring.security.InMemoryAccountLockoutService;
import zrouga.spring.security.InMemoryEmailVerificationTokenStore;
import zrouga.spring.security.InMemoryPasswordHistoryStore;
import zrouga.spring.security.InMemoryPasswordResetTokenStore;
import zrouga.spring.security.InMemoryTwoFactorSecretStore;
import zrouga.spring.security.PasswordHistoryStore;
import zrouga.spring.security.PasswordPolicy;
import zrouga.spring.security.PasswordResetEmailSender;
import zrouga.spring.security.PasswordResetService;
import zrouga.spring.security.PasswordResetTokenStore;
import zrouga.spring.security.RefreshTokenService;
import zrouga.spring.security.RefreshTokenStore;
import zrouga.spring.security.SmtpEmailVerificationEmailSender;
import zrouga.spring.security.SmtpPasswordResetEmailSender;
import zrouga.spring.security.TwoFactorSecretStore;
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
import org.springframework.context.ApplicationEventPublisher;
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
    public AuthTokenFilter authenticationJwtTokenFilter(JwtUtils jwtUtils,
            AccessTokenRevocation accessTokenRevocation) {
        return new AuthTokenFilter(jwtUtils, accessTokenRevocation);
    }

    /** Store de révocation par défaut en mémoire — déclarez le vôtre (Redis…) pour persister. */
    @Bean
    @ConditionalOnMissingBean(AccessTokenRevocationStore.class)
    public AccessTokenRevocationStore accessTokenRevocationStore() {
        return new InMemoryAccessTokenRevocationStore();
    }

    @Bean
    @ConditionalOnMissingBean(AccessTokenRevocation.class)
    public AccessTokenRevocation accessTokenRevocation(ZrougaSecurityProperties properties,
            ObjectProvider<AccessTokenRevocationStore> storeProvider) {
        return new AccessTokenRevocation(properties, storeProvider);
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
    @ConditionalOnMissingBean(AccountLockoutService.class)
    public AccountLockoutService accountLockoutService(ZrougaSecurityProperties properties) {
        return new InMemoryAccountLockoutService(properties);
    }

    @Bean
    @ConditionalOnMissingBean(PasswordPolicy.class)
    public PasswordPolicy passwordPolicy(ZrougaSecurityProperties properties) {
        return new PasswordPolicy(properties);
    }

    @Bean
    @ConditionalOnMissingBean(PasswordHistoryStore.class)
    public PasswordHistoryStore passwordHistoryStore() {
        return new InMemoryPasswordHistoryStore();
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
            ObjectProvider<AuthUserCreator> creatorProvider,
            AccountLockoutService accountLockoutService,
            PasswordPolicy passwordPolicy,
            ZrougaSecurityProperties properties,
            AccessTokenRevocation accessTokenRevocation,
            ApplicationEventPublisher eventPublisher,
            TwoFactorSecretStore twoFactorSecretStore) {
        return new AuthService(authenticationManager, userProvider, jwtUtils, refreshTokenService,
                loginRateLimiter, passwordEncoder, creatorProvider, accountLockoutService, passwordPolicy,
                properties, accessTokenRevocation, eventPublisher, twoFactorSecretStore);
    }

    @Bean
    @ConditionalOnMissingBean(AuthResource.class)
    public AuthResource authResource(AuthService authService, PasswordResetService passwordResetService,
            EmailVerificationService emailVerificationService, ZrougaSecurityProperties properties) {
        return new AuthResource(authService, passwordResetService, emailVerificationService, properties);
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
            PasswordEncoder passwordEncoder,
            PasswordPolicy passwordPolicy,
            PasswordHistoryStore passwordHistoryStore,
            ApplicationEventPublisher eventPublisher) {
        return new PasswordResetService(properties, userProvider, passwordUpdater, emailSender,
                passwordResetTokenStore, refreshTokenService, loginRateLimiter, passwordEncoder,
                passwordPolicy, passwordHistoryStore, eventPublisher);
    }

    @Bean
    @ConditionalOnMissingBean(TokenControllerAdvice.class)
    public TokenControllerAdvice tokenControllerAdvice() {
        return new TokenControllerAdvice();
    }

    @Bean
    @ConditionalOnMissingBean(EmailVerificationTokenStore.class)
    public EmailVerificationTokenStore emailVerificationTokenStore() {
        return new InMemoryEmailVerificationTokenStore();
    }

    /** Secrets TOTP par défaut en mémoire — déclarez le vôtre pour persister/chiffrer. */
    @Bean
    @ConditionalOnMissingBean(TwoFactorSecretStore.class)
    public TwoFactorSecretStore twoFactorSecretStore() {
        return new InMemoryTwoFactorSecretStore();
    }

    @Bean
    @ConditionalOnMissingBean(EmailVerificationEmailSender.class)
    @ConditionalOnProperty(prefix = "zrouga.security", name = "email-verification-enabled", havingValue = "true")
    public SmtpEmailVerificationEmailSender smtpEmailVerificationEmailSender(
            ObjectProvider<JavaMailSender> mailSender,
            ZrougaSecurityProperties properties,
            ObjectProvider<TaskExecutor> taskExecutor) {
        return new SmtpEmailVerificationEmailSender(mailSender, properties, taskExecutor);
    }

    @Bean
    @ConditionalOnMissingBean(EmailVerificationService.class)
    public EmailVerificationService emailVerificationService(
            ZrougaSecurityProperties properties,
            ObjectProvider<AuthUserProvider> userProvider,
            ObjectProvider<AuthUserEmailVerifier> emailVerifier,
            ObjectProvider<EmailVerificationEmailSender> emailSender,
            EmailVerificationTokenStore emailVerificationTokenStore,
            LoginRateLimiter loginRateLimiter,
            ApplicationEventPublisher eventPublisher) {
        return new EmailVerificationService(properties, userProvider, emailVerifier, emailSender,
                emailVerificationTokenStore, loginRateLimiter, eventPublisher);
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

    /**
     * Validation de {@code zrouga.security.auth-mode} et
     * {@code cookie-same-site} : échec explicite au démarrage sur une valeur
     * inconnue (plutôt qu'un repli silencieux), et {@code None} exige
     * {@code cookie-secure=true} (exigence des navigateurs modernes).
     */
    @Bean
    public InitializingBean zrougaAuthModeValid(ZrougaSecurityProperties properties) {
        return () -> {
            String mode = properties.getAuthMode();
            if (!"header".equalsIgnoreCase(mode) && !"cookie".equalsIgnoreCase(mode)) {
                throw new IllegalStateException(
                        "zrouga.security.auth-mode doit valoir 'header' ou 'cookie' (valeur actuelle : '"
                                + mode + "').");
            }

            String sameSite = properties.getCookieSameSite();
            boolean known = "Lax".equalsIgnoreCase(sameSite)
                    || "Strict".equalsIgnoreCase(sameSite)
                    || "None".equalsIgnoreCase(sameSite);
            if (!known) {
                throw new IllegalStateException(
                        "zrouga.security.cookie-same-site doit valoir 'Lax', 'Strict' ou 'None' (valeur actuelle : '"
                                + sameSite + "').");
            }
            if ("None".equalsIgnoreCase(sameSite) && !properties.isCookieSecure()) {
                throw new IllegalStateException(
                        "zrouga.security.cookie-same-site=None exige zrouga.security.cookie-secure=true "
                                + "(les navigateurs refusent un cookie SameSite=None non sécurisé).");
            }
        };
    }
}
