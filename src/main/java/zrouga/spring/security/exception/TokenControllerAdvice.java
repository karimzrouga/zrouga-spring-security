package zrouga.spring.security.exception;

import zrouga.spring.security.payload.ApiError;

import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

/**
 * Restitue les erreurs du starter dans un format unifié {@link ApiError}.
 *
 * <p>Restreint aux contrôleurs du starter ({@code basePackages}) : les exceptions de
 * votre application ne sont jamais interceptées ici — définissez votre propre advice
 * pour vos endpoints.</p>
 *
 * <p>Statut HTTP lu sur {@code @ResponseStatus} de l'exception (une seule méthode de
 * traitement pour toutes), code machine lu sur {@link AuthException#code()}.</p>
 */
@RestControllerAdvice(basePackages = "zrouga.spring.security")
public class TokenControllerAdvice {

    @ExceptionHandler({ TokenRefreshException.class, RateLimitException.class, EmailAlreadyUsedException.class,
            SignupNotSupportedException.class, PasswordResetNotSupportedException.class,
            InvalidResetTokenException.class })
    public ResponseEntity<ApiError> handleAuthException(AuthException ex, WebRequest request) {
        ResponseStatus status = AnnotatedElementUtils.findMergedAnnotation(ex.getClass(), ResponseStatus.class);
        HttpStatus httpStatus = status != null ? status.value() : HttpStatus.INTERNAL_SERVER_ERROR;
        return error(httpStatus, ex.code(), ex.getMessage(), request);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidationException(MethodArgumentNotValidException ex, WebRequest request) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .map(this::formatFieldError)
                .reduce((a, b) -> a + "; " + b)
                .orElse("Invalid request");
        return error(HttpStatus.BAD_REQUEST, "validation_error", message, request);
    }

    private String formatFieldError(FieldError fieldError) {
        return fieldError.getField() + ": " + fieldError.getDefaultMessage();
    }

    private ResponseEntity<ApiError> error(HttpStatus status, String code, String message, WebRequest request) {
        String path = request.getDescription(false).replace("uri=", "");
        ApiError body = ApiError.of(status.value(), code, status.getReasonPhrase(), message, path);
        return ResponseEntity.status(status).body(body);
    }
}
