package zrouga.spring.security.payload;

import java.time.Instant;

/**
 * Corps d'erreur unifié retourné par le starter pour les réponses 400, 401, 403, 409,
 * 429 et 501.
 *
 * @param status    code HTTP
 * @param code      code machine stable (ex. {@code rate_limit_exceeded}) — à utiliser
 *                  côté client, jamais le message
 * @param error     libellé court du statut (ex. {@code Unauthorized})
 * @param message   message destiné au client (peut changer sans préavis)
 * @param path      chemin de la requête
 * @param timestamp horodatage ISO-8601
 */
public record ApiError(int status, String code, String error, String message, String path, String timestamp) {

    /**
     * Construit une erreur avec un horodatage ISO-8601 courant.
     *
     * @param status  code HTTP
     * @param code    code machine stable
     * @param error   libellé court du statut
     * @param message message destiné au client
     * @param path    chemin de la requête
     * @return l'erreur correspondante
     */
    public static ApiError of(int status, String code, String error, String message, String path) {
        return new ApiError(status, code, error, message, path, Instant.now().toString());
    }
}
