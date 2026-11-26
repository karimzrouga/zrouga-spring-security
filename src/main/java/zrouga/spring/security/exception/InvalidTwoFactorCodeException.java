package zrouga.spring.security.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/** Code TOTP absent, incorrect ou expiré (setup/enable/verify/disable). */
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class InvalidTwoFactorCodeException extends AuthException {

    private static final long serialVersionUID = 1L;

    public InvalidTwoFactorCodeException(String message) {
        super("invalid_two_factor_code", message);
    }
}
