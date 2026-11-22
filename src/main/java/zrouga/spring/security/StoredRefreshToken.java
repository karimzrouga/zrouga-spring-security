package zrouga.spring.security;

import java.time.Instant;

public record StoredRefreshToken(String token, long userId, Instant expiryDate) {
}
