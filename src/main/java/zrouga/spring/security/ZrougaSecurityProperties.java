package zrouga.spring.security;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "zrouga.security")
public class ZrougaSecurityProperties {

    private String jwtSecret;

    private long jwtExpirationMs = 1_800_000L;

    private long jwtRefreshExpirationMs = 86_400_000L;

    private List<String> publicPaths = List.of("/api/auth/**");

    public String getJwtSecret() {
        return jwtSecret;
    }

    public void setJwtSecret(String jwtSecret) {
        this.jwtSecret = jwtSecret;
    }

    public long getJwtExpirationMs() {
        return jwtExpirationMs;
    }

    public void setJwtExpirationMs(long jwtExpirationMs) {
        this.jwtExpirationMs = jwtExpirationMs;
    }

    public long getJwtRefreshExpirationMs() {
        return jwtRefreshExpirationMs;
    }

    public void setJwtRefreshExpirationMs(long jwtRefreshExpirationMs) {
        this.jwtRefreshExpirationMs = jwtRefreshExpirationMs;
    }

    public List<String> getPublicPaths() {
        return publicPaths;
    }

    public void setPublicPaths(List<String> publicPaths) {
        this.publicPaths = publicPaths;
    }
}
