package zrouga.spring.security;

import java.util.ArrayList;
import java.util.List;

import zrouga.spring.security.exception.WeakPasswordException;

/**
 * Politique de mot de passe — fonctionnalité <b>optionnelle</b>, active uniquement si
 * {@code zrouga.security.password-policy-enabled=true}.
 *
 * <p>Règles (toutes surchargeables via {@code password-*}) : longueur minimale,
 * majuscule, minuscule, chiffre, caractère spécial (non alphanumérique, non espace).
 * La première violation lève {@link WeakPasswordException} ({@code 400 weak_password})
 * avec la liste complète des règles manquantes. S'applique à {@code /signup} et à
 * {@code /reset-password} — l'anti-réutilisation (historique) est géré par
 * {@link PasswordHistoryStore} dans {@link PasswordResetService}.</p>
 *
 * <p>Bean surchargeable : déclarez votre propre {@code PasswordPolicy} pour des règles
 * personnalisées (dictionnaires, NIST SP 800-63B, …).</p>
 */
public class PasswordPolicy {

    private static final String SPECIALS = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

    private final boolean enabled;
    private final int minLength;
    private final boolean requireUppercase;
    private final boolean requireLowercase;
    private final boolean requireDigit;
    private final boolean requireSpecial;

    public PasswordPolicy(ZrougaSecurityProperties properties) {
        this.enabled = properties.isPasswordPolicyEnabled();
        this.minLength = Math.max(1, properties.getPasswordMinLength());
        this.requireUppercase = properties.isPasswordRequireUppercase();
        this.requireLowercase = properties.isPasswordRequireLowercase();
        this.requireDigit = properties.isPasswordRequireDigit();
        this.requireSpecial = properties.isPasswordRequireSpecial();
    }

    /**
     * Valide le mot de passe brut contre la politique.
     *
     * @param rawPassword mot de passe en clair (null ou vide = violation)
     * @throws WeakPasswordException à la première règle violée, message listant
     *         <b>toutes</b> les règles manquantes
     */
    public void validate(String rawPassword) {
        if (!enabled) {
            return;
        }
        String password = rawPassword == null ? "" : rawPassword;
        List<String> violations = new ArrayList<>();

        if (password.length() < minLength) {
            violations.add("be at least " + minLength + " characters long");
        }
        List<String> missingClasses = new ArrayList<>();
        if (requireUppercase && password.chars().noneMatch(Character::isUpperCase)) {
            missingClasses.add("an uppercase letter");
        }
        if (requireLowercase && password.chars().noneMatch(Character::isLowerCase)) {
            missingClasses.add("a lowercase letter");
        }
        if (requireDigit && password.chars().noneMatch(Character::isDigit)) {
            missingClasses.add("a digit");
        }
        if (requireSpecial && password.chars().noneMatch(c -> SPECIALS.indexOf(c) >= 0)) {
            missingClasses.add("a special character");
        }
        if (!missingClasses.isEmpty()) {
            violations.add("contain " + String.join(", ", missingClasses));
        }

        if (!violations.isEmpty()) {
            throw new WeakPasswordException(
                    "Password must " + String.join(" and ", violations) + ".");
        }
    }
}
