package zrouga.spring.security.payload;

import java.time.Instant;

/**
 * Corps d'erreur unifié retourné par le starter pour les réponses 400, 401, 403 et 429.
 */
public record ApiError(int status, String error, String message, String path, String timestamp) {

    /**
     * Construit une erreur avec un horodatage ISO-8601 courant.
     *
     * @param status  code HTTP
     * @param error   libellé court du statut (ex. {@code Unauthorized})
     * @param message message destiné au client
     * @param path    chemin de la requête
     * @return l'erreur correspondante
     */
    public static ApiError of(int status, String error, String message, String path) {
        return new ApiError(status, error, message, path, Instant.now().toString());
    }
}
