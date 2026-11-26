package zrouga.spring.security.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/** Challenge {@code twoFactorToken} absent, invalide ou expiré. */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class TwoFactorTokenException extends AuthException {

    private static final long serialVersionUID = 1L;

    public TwoFactorTokenException(String message) {
        super("two_factor_token_invalid", message);
    }
}
