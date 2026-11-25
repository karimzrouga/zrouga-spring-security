package zrouga.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import zrouga.spring.security.exception.WeakPasswordException;

import org.junit.jupiter.api.Test;

/**
 * Politique de mot de passe : désactivation par défaut, longueur, classes de
 * caractères, messages listant toutes les règles manquantes.
 */
class PasswordPolicyTest {

    private static ZrougaSecurityProperties properties() {
        return new ZrougaSecurityProperties();
    }

    private static PasswordPolicy enabledPolicy() {
        ZrougaSecurityProperties properties = new ZrougaSecurityProperties();
        properties.setPasswordPolicyEnabled(true);
        return new PasswordPolicy(properties);
    }

    @Test
    void desactiveValideNimporteQuelMotDePasse() {
        PasswordPolicy policy = new PasswordPolicy(properties());

        assertThatCode(() -> policy.validate("1")).doesNotThrowAnyException();
        assertThatCode(() -> policy.validate(null)).doesNotThrowAnyException();
        assertThatCode(() -> policy.validate("")).doesNotThrowAnyException();
    }

    @Test
    void motDePasseConformePasse() {
        assertThatCode(() -> enabledPolicy().validate("Admin@1234")).doesNotThrowAnyException();
        assertThatCode(() -> enabledPolicy().validate("zF9!xQ2#pL")).doesNotThrowAnyException();
    }

    @Test
    void longueurMinimalePersonnalisee() {
        ZrougaSecurityProperties properties = properties();
        properties.setPasswordPolicyEnabled(true);
        properties.setPasswordMinLength(12);

        assertThatThrownBy(() -> new PasswordPolicy(properties).validate("Ab1@xxxx"))
                .isInstanceOf(WeakPasswordException.class)
                .hasMessageContaining("be at least 12 characters long")
                .satisfies(ex -> assertThat(((WeakPasswordException) ex).code()).isEqualTo("weak_password"));
    }

    @Test
    void toutesLesClassesManquantesListees() {
        assertThatThrownBy(() -> enabledPolicy().validate("abcdefghij"))
                .isInstanceOf(WeakPasswordException.class)
                .hasMessageContaining("an uppercase letter")
                .hasMessageContaining("a digit")
                .hasMessageContaining("a special character")
                .hasMessageNotContaining("lowercase");
    }

    @Test
    void majusculeEtMinusculeManquantes() {
        assertThatThrownBy(() -> enabledPolicy().validate("12345678!"))
                .isInstanceOf(WeakPasswordException.class)
                .hasMessageContaining("an uppercase letter")
                .hasMessageContaining("a lowercase letter")
                .hasMessageNotContaining("digit");
    }

    @Test
    void espaceNestPasUnCaractereSpecial() {
        assertThatThrownBy(() -> enabledPolicy().validate("Abcdefg1 "))
                .isInstanceOf(WeakPasswordException.class)
                .hasMessageContaining("a special character");

        assertThatCode(() -> enabledPolicy().validate("Abcdefg1!")).doesNotThrowAnyException();
    }

    @Test
    void motDePasseVideEstUneViolation() {
        assertThatThrownBy(() -> enabledPolicy().validate(""))
                .isInstanceOf(WeakPasswordException.class)
                .hasMessageContaining("be at least 8 characters long");
    }

    @Test
    void reglesDesactiveesUneParUne() {
        ZrougaSecurityProperties properties = properties();
        properties.setPasswordPolicyEnabled(true);
        properties.setPasswordRequireSpecial(false);
        properties.setPasswordRequireUppercase(false);
        properties.setPasswordRequireDigit(false);
        properties.setPasswordRequireLowercase(false);
        properties.setPasswordMinLength(1);

        assertThatCode(() -> new PasswordPolicy(properties).validate("x")).doesNotThrowAnyException();
    }
}
