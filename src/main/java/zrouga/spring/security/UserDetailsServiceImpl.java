package zrouga.spring.security;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.transaction.annotation.Transactional;

public class UserDetailsServiceImpl implements UserDetailsService, InitializingBean {

    private final ObjectProvider<AuthUserProvider> userProvider;

    private AuthUserProvider authUserProvider;

    public UserDetailsServiceImpl(ObjectProvider<AuthUserProvider> userProvider) {
        this.userProvider = userProvider;
    }

    @Override
    public void afterPropertiesSet() {
        this.authUserProvider = userProvider.getIfAvailable();
        if (this.authUserProvider == null) {
            throw new IllegalStateException(AuthUserProvider.MISSING_BEAN_MESSAGE);
        }
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AuthUser user = authUserProvider.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));

        return UserDetailsImpl.build(user);
    }
}
