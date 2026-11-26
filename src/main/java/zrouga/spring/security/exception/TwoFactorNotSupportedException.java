package zrouga.spring.security.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/** {@code zrouga.security.two-factor-enabled=false} mais endpoint 2FA appelé. */
@ResponseStatus(HttpStatus.NOT_IMPLEMENTED)
public class TwoFactorNotSupportedException extends AuthException {

    private static final long serialVersionUID = 1L;

    public TwoFactorNotSupportedException(String message) {
        super("two_factor_not_supported", message);
    }
}
