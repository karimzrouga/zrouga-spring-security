package zrouga.spring.security.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.FORBIDDEN)
public class TokenRefreshException extends AuthException {

    private static final long serialVersionUID = 1L;

    public TokenRefreshException(String message) {
        super("refresh_token_rejected", message);
    }
}
