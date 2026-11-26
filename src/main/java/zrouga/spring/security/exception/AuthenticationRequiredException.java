package zrouga.spring.security.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/** Endpoint 2FA appelé sans utilisateur authentifié (setup/enable/disable). */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class AuthenticationRequiredException extends AuthException {

    private static final long serialVersionUID = 1L;

    public AuthenticationRequiredException(String message) {
        super("authentication_required", message);
    }
}
