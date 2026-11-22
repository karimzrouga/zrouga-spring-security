package zrouga.spring.security.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_IMPLEMENTED)
public class PasswordResetNotSupportedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public PasswordResetNotSupportedException(String message) {
        super(message);
    }
}
