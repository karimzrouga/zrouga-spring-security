package zrouga.spring.security;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * Purge périodique des refresh tokens expirés (activée via
 * {@code zrouga.security.cleanup-enabled=true}).
 */
public class RefreshTokenCleanup {

    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenCleanup.class);

    private final RefreshTokenStore refreshTokenStore;

    public RefreshTokenCleanup(RefreshTokenStore refreshTokenStore) {
        this.refreshTokenStore = refreshTokenStore;
    }

    @Scheduled(fixedDelayString = "${zrouga.security.cleanup-fixed-delay-ms:3600000}")
    public void deleteExpiredTokens() {
        int deleted = refreshTokenStore.deleteExpired(Instant.now());
        if (deleted > 0) {
            logger.info("Refresh tokens expirés purgés : {}", deleted);
        }
    }
}
