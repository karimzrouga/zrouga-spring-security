package zrouga.spring.security;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * Purge périodique des jetons expirés — refresh tokens <b>et</b> jetons de
 * réinitialisation du mot de passe (activée via
 * {@code zrouga.security.cleanup-enabled=true}).
 */
public class RefreshTokenCleanup {

    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenCleanup.class);

    private final RefreshTokenStore refreshTokenStore;
    private final PasswordResetTokenStore passwordResetTokenStore;

    public RefreshTokenCleanup(RefreshTokenStore refreshTokenStore,
            PasswordResetTokenStore passwordResetTokenStore) {
        this.refreshTokenStore = refreshTokenStore;
        this.passwordResetTokenStore = passwordResetTokenStore;
    }

    @Scheduled(fixedDelayString = "${zrouga.security.cleanup-fixed-delay-ms:3600000}")
    public void deleteExpiredTokens() {
        Instant now = Instant.now();
        int deleted = refreshTokenStore.deleteExpired(now);
        if (deleted > 0) {
            logger.info("Refresh tokens expirés purgés : {}", deleted);
        }
        int deletedResets = passwordResetTokenStore.deleteExpired(now);
        if (deletedResets > 0) {
            logger.info("Jetons de réinitialisation expirés purgés : {}", deletedResets);
        }
    }
}
