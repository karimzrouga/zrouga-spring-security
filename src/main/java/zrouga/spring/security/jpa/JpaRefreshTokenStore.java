package zrouga.spring.security.jpa;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import zrouga.spring.security.RefreshTokenStore;
import zrouga.spring.security.StoredRefreshToken;
import zrouga.spring.security.TokenHashing;

import jakarta.persistence.EntityManager;

import org.springframework.transaction.annotation.Transactional;

/**
 * Stockage JPA : seules les empreintes SHA-256 des jetons sont persistées.
 * L'empreinte n'est jamais renvoyée — {@code findByToken}/{@code revoke} reconstruisent
 * le record avec le jeton brut fourni en entrée.
 */
public class JpaRefreshTokenStore implements RefreshTokenStore {

    private final EntityManager entityManager;

    public JpaRefreshTokenStore(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    @Transactional
    public StoredRefreshToken save(long userId, Instant expiryDate) {
        return save(userId, expiryDate, null, null);
    }

    @Override
    @Transactional
    public StoredRefreshToken save(long userId, Instant expiryDate, String ip, String userAgent) {
        String raw = UUID.randomUUID().toString();
        RefreshTokenEntity entity = new RefreshTokenEntity();
        entity.setUserId(userId);
        entity.setToken(TokenHashing.sha256Hex(raw));
        entity.setExpiryDate(expiryDate);
        entity.setRevoked(false);
        entity.setIp(ip);
        entity.setUserAgent(userAgent);
        entityManager.persist(entity);
        return new StoredRefreshToken(raw, userId, expiryDate, false, ip, userAgent);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<StoredRefreshToken> findByToken(String token) {
        if (token == null) {
            return Optional.empty();
        }
        List<RefreshTokenEntity> results = entityManager
                .createQuery("SELECT r FROM refreshtoken r WHERE r.token = :token", RefreshTokenEntity.class)
                .setParameter("token", TokenHashing.sha256Hex(token))
                .setMaxResults(1)
                .getResultList();
        return results.stream()
                .findFirst()
                .map(entity -> new StoredRefreshToken(token, entity.getUserId(), entity.getExpiryDate(),
                        entity.isRevoked(), entity.getIp(), entity.getUserAgent()));
    }

    @Override
    @Transactional
    public boolean revoke(String token) {
        if (token == null) {
            return false;
        }
        int updated = entityManager
                .createQuery("UPDATE refreshtoken r SET r.revoked = true "
                        + "WHERE r.token = :token AND r.revoked = false")
                .setParameter("token", TokenHashing.sha256Hex(token))
                .executeUpdate();
        return updated == 1;
    }

    @Override
    @Transactional
    public int deleteByUserId(long userId) {
        return entityManager.createQuery("DELETE FROM refreshtoken r WHERE r.userId = :userId")
                .setParameter("userId", userId)
                .executeUpdate();
    }

    @Override
    @Transactional
    public int deleteExpired(Instant now) {
        return entityManager.createQuery("DELETE FROM refreshtoken r WHERE r.expiryDate < :now")
                .setParameter("now", now)
                .executeUpdate();
    }
}
