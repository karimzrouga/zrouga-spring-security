package zrouga.spring.security.payload;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Réponse de {@code POST /api/auth/signin} :
 *
 * <ul>
 * <li><b>2FA désactivé</b> (ou compte sans secret) —
 *     {@code token} + {@code refreshToken} (comportement historique, les champs
 *     {@code twoFactor*} sont omis) ;</li>
 * <li><b>2FA activé</b> — {@code twoFactorRequired=true} et
 *     {@code twoFactorToken} (challenge éphémère) <b>au lieu</b> des tokens :
 *     échangez-les sur {@code POST /api/auth/2fa/verify}.</li>
 * </ul>
 *
 * @param token             access token JWT (Bearer), {@code null} si challenge
 * @param type              type d'authentification ({@code Bearer})
 * @param refreshToken      refresh token, {@code null} si challenge
 * @param twoFactorRequired {@code true} si une seconde étape est exigée
 * @param twoFactorToken    challenge 2FA éphémère, {@code null} sinon
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record JwtResponse(String token, String type, String refreshToken, Boolean twoFactorRequired,
        String twoFactorToken) {

    public JwtResponse(String token, String refreshToken) {
        this(token, "Bearer", refreshToken, null, null);
    }

    public JwtResponse(String token, String type, String refreshToken) {
        this(token, type, refreshToken, null, null);
    }

    /** Réponse de signin pour un compte 2FA activé — aucun token émis. */
    public static JwtResponse twoFactorChallenge(String challengeToken) {
        return new JwtResponse(null, null, null, true, challengeToken);
    }
}
