package zrouga.spring.security.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/** Jeton de vérification d'e-mail absent, déjà utilisé ou expiré. */
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class InvalidEmailVerificationTokenException extends AuthException {

    private static final long serialVersionUID = 1L;

    public InvalidEmailVerificationTokenException(String message) {
        super("verification_token_invalid", message);
    }
}
