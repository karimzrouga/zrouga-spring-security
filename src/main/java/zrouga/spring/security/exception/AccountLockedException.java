package zrouga.spring.security.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Compte verrouillé après {@code zrouga.security.lockout-max-attempts} connexions
 * échouées — répond {@code 423 account_locked} pendant toute la durée du verrou
 * (voir {@code zrouga.security.lockout-enabled}).
 */
@ResponseStatus(HttpStatus.LOCKED)
public class AccountLockedException extends AuthException {

    private static final long serialVersionUID = 1L;

    public AccountLockedException(String message) {
        super("account_locked", message);
    }
}
