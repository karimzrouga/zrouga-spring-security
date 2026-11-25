package zrouga.spring.security.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Mot de passe refusé par la politique {@code zrouga.security.password-policy-enabled}
 * (longueur, complexité ou réutilisation d'un mot de passe récent) —
 * répond {@code 400 weak_password}.
 */
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class WeakPasswordException extends AuthException {

    private static final long serialVersionUID = 1L;

    public WeakPasswordException(String message) {
        super("weak_password", message);
    }
}
