package zrouga.spring.security.autoconfigure;

import zrouga.spring.security.RefreshTokenStore;
import zrouga.spring.security.RefreshTokenCleanup;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Purge périodique des refresh tokens expirés — optionnelle, activée par
 * {@code zrouga.security.cleanup-enabled=true}.
 */
@AutoConfiguration(after = ZrougaSecurityAutoConfiguration.class)
@ConditionalOnProperty(prefix = "zrouga.security", name = "cleanup-enabled", havingValue = "true")
@EnableScheduling
public class ZrougaCleanupAutoConfiguration {

    @Bean
    public RefreshTokenCleanup zrougaRefreshTokenCleanup(RefreshTokenStore refreshTokenStore) {
        return new RefreshTokenCleanup(refreshTokenStore);
    }
}
