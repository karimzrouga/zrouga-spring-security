package zrouga.spring.security.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.TOO_MANY_REQUESTS)
public class RateLimitException extends AuthException {

    private static final long serialVersionUID = 1L;

    public RateLimitException(String message) {
        super("rate_limit_exceeded", message);
    }
}
