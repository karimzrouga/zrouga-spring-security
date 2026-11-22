package zrouga.spring.security.autoconfigure;

import zrouga.spring.security.RefreshTokenStore;
import zrouga.spring.security.jpa.JpaRefreshTokenStore;
import zrouga.spring.security.jpa.RefreshTokenEntity;

import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.orm.jpa.SharedEntityManagerCreator;

@AutoConfiguration
@ConditionalOnClass(EntityManager.class)
@ConditionalOnMissingBean(RefreshTokenStore.class)
@EntityScan(basePackageClasses = RefreshTokenEntity.class)
public class ZrougaJpaRefreshTokenAutoConfiguration {

    @Bean
    public JpaRefreshTokenStore jpaRefreshTokenStore(EntityManagerFactory entityManagerFactory) {
        return new JpaRefreshTokenStore(SharedEntityManagerCreator.createSharedEntityManager(entityManagerFactory));
    }
}
