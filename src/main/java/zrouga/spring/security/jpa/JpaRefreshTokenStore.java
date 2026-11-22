package zrouga.spring.security.jpa;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import zrouga.spring.security.RefreshTokenStore;
import zrouga.spring.security.StoredRefreshToken;

import jakarta.persistence.EntityManager;

import org.springframework.transaction.annotation.Transactional;

public class JpaRefreshTokenStore implements RefreshTokenStore {

    private final EntityManager entityManager;

    public JpaRefreshTokenStore(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    @Transactional
    public StoredRefreshToken save(long userId, Instant expiryDate) {
        RefreshTokenEntity entity = new RefreshTokenEntity();
        entity.setUserId(userId);
        entity.setToken(UUID.randomUUID().toString());
        entity.setExpiryDate(expiryDate);
        entityManager.persist(entity);
        return new StoredRefreshToken(entity.getToken(), entity.getUserId(), entity.getExpiryDate());
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<StoredRefreshToken> findByToken(String token) {
        return entityManager
                .createQuery("SELECT r FROM refreshtoken r WHERE r.token = :token", RefreshTokenEntity.class)
                .setParameter("token", token)
                .getResultList()
                .stream()
                .findFirst()
                .map(entity -> new StoredRefreshToken(entity.getToken(), entity.getUserId(), entity.getExpiryDate()));
    }

    @Override
    @Transactional
    public void deleteByToken(String token) {
        entityManager.createQuery("DELETE FROM refreshtoken r WHERE r.token = :token")
                .setParameter("token", token)
                .executeUpdate();
    }

    @Override
    @Transactional
    public int deleteByUserId(long userId) {
        return entityManager.createQuery("DELETE FROM refreshtoken r WHERE r.userId = :userId")
                .setParameter("userId", userId)
                .executeUpdate();
    }
}
