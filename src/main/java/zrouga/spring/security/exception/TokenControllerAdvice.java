package zrouga.spring.security.exception;

import zrouga.spring.security.payload.ApiError;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

/**
 * Restitue toutes les erreurs du starter dans un format unifié {@link ApiError}.
 */
@RestControllerAdvice
public class TokenControllerAdvice {

    @ExceptionHandler(TokenRefreshException.class)
    public ResponseEntity<ApiError> handleTokenRefreshException(TokenRefreshException ex, WebRequest request) {
        return error(HttpStatus.FORBIDDEN, ex.getMessage(), request);
    }

    @ExceptionHandler(RateLimitException.class)
    public ResponseEntity<ApiError> handleRateLimitException(RateLimitException ex, WebRequest request) {
        return error(HttpStatus.TOO_MANY_REQUESTS, ex.getMessage(), request);
    }

    @ExceptionHandler(EmailAlreadyUsedException.class)
    public ResponseEntity<ApiError> handleEmailAlreadyUsedException(EmailAlreadyUsedException ex, WebRequest request) {
        return error(HttpStatus.CONFLICT, ex.getMessage(), request);
    }

    @ExceptionHandler(SignupNotSupportedException.class)
    public ResponseEntity<ApiError> handleSignupNotSupportedException(
            SignupNotSupportedException ex, WebRequest request) {
        return error(HttpStatus.NOT_IMPLEMENTED, ex.getMessage(), request);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidationException(MethodArgumentNotValidException ex, WebRequest request) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .map(this::formatFieldError)
                .reduce((a, b) -> a + "; " + b)
                .orElse("Requête invalide");
        return error(HttpStatus.BAD_REQUEST, message, request);
    }

    private String formatFieldError(FieldError fieldError) {
        return fieldError.getField() + " : " + fieldError.getDefaultMessage();
    }

    private ResponseEntity<ApiError> error(HttpStatus status, String message, WebRequest request) {
        String path = request.getDescription(false).replace("uri=", "");
        ApiError body = ApiError.of(status.value(), status.getReasonPhrase(), message, path);
        return ResponseEntity.status(status).body(body);
    }
}
