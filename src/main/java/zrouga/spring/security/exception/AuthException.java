package zrouga.spring.security.exception;

/**
 * Exception métier du starter, portant un <b>code machine</b> stable renvoyé dans
 * {@code ApiError.code} — les clients branchent leur logique sur ce code, jamais sur
 * le message (les messages peuvent changer, les codes ne changent pas sans
 * increment de version).
 *
 * <p>Chaque sous-classe porte aussi {@code @ResponseStatus} : l'advice du starter lit
 * cette annotation pour construire la réponse HTTP.</p>
 */
public abstract class AuthException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final String code;

    protected AuthException(String code, String message) {
        super(message);
        this.code = code;
    }

    /**
     * @return code machine stable (ex. {@code rate_limit_exceeded})
     */
    public String code() {
        return code;
    }
}
