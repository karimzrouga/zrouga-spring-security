package zrouga.spring.security.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/** {@code zrouga.security.email-verification-enabled=false} mais endpoint appelé. */
@ResponseStatus(HttpStatus.NOT_IMPLEMENTED)
public class EmailVerificationNotSupportedException extends AuthException {

    private static final long serialVersionUID = 1L;

    public EmailVerificationNotSupportedException(String message) {
        super("verification_not_supported", message);
    }
}
