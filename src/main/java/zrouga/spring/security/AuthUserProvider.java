package zrouga.spring.security;

import java.util.Optional;

public interface AuthUserProvider {

    Optional<AuthUser> findByEmail(String email);

    Optional<AuthUser> findById(Long id);
}
