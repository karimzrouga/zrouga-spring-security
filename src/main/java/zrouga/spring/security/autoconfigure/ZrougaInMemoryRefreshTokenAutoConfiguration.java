package zrouga.spring.security.autoconfigure;

import zrouga.spring.security.InMemoryRefreshTokenStore;
import zrouga.spring.security.RefreshTokenStore;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

@AutoConfiguration(after = ZrougaJpaRefreshTokenAutoConfiguration.class)
@ConditionalOnMissingBean(RefreshTokenStore.class)
public class ZrougaInMemoryRefreshTokenAutoConfiguration {

    @Bean
    public InMemoryRefreshTokenStore inMemoryRefreshTokenStore() {
        return new InMemoryRefreshTokenStore();
    }
}
