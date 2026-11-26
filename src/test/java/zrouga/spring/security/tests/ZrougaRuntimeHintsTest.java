package zrouga.spring.security.tests;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import zrouga.spring.security.ZrougaRuntimeHints;
import zrouga.spring.security.payload.ApiError;
import zrouga.spring.security.payload.ForgotPasswordRequest;
import zrouga.spring.security.payload.JwtResponse;
import zrouga.spring.security.payload.LoginRequest;
import zrouga.spring.security.payload.MessageResponse;
import zrouga.spring.security.payload.ResendVerificationRequest;
import zrouga.spring.security.payload.ResetPasswordRequest;
import zrouga.spring.security.payload.SignupRequest;
import zrouga.spring.security.payload.TokenRefreshRequest;
import zrouga.spring.security.payload.TokenRefreshResponse;
import zrouga.spring.security.payload.TwoFactorCodeRequest;
import zrouga.spring.security.payload.TwoFactorSetupResponse;
import zrouga.spring.security.payload.TwoFactorVerifyRequest;
import zrouga.spring.security.payload.VerifyEmailRequest;

import org.junit.jupiter.api.Test;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.predicate.RuntimeHintsPredicates;

class ZrougaRuntimeHintsTest {

    private static final List<Class<?>> PAYLOADS = List.of(
            ApiError.class,
            ForgotPasswordRequest.class,
            JwtResponse.class,
            LoginRequest.class,
            MessageResponse.class,
            ResendVerificationRequest.class,
            ResetPasswordRequest.class,
            SignupRequest.class,
            TokenRefreshRequest.class,
            TokenRefreshResponse.class,
            TwoFactorCodeRequest.class,
            TwoFactorSetupResponse.class,
            TwoFactorVerifyRequest.class,
            VerifyEmailRequest.class);

    private RuntimeHints hints() {
        RuntimeHints hints = new RuntimeHints();
        new ZrougaRuntimeHints().registerHints(hints, getClass().getClassLoader());
        return hints;
    }

    @Test
    void tousLesDtoSontEnregistresPourLaReflection() {
        RuntimeHints runtimeHints = hints();
        for (Class<?> payload : PAYLOADS) {
            assertThat(RuntimeHintsPredicates.reflection().onType(payload).test(runtimeHints))
                    .as(payload.getSimpleName())
                    .isTrue();
        }
    }

    @Test
    void registrarDeclareDansLesAotFactories() throws Exception {
        try (InputStream stream = getClass().getClassLoader()
                .getResourceAsStream("META-INF/spring/aot.factories")) {
            assertThat(stream).isNotNull();
            String content = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
            assertThat(content)
                    .contains("org.springframework.aot.hint.RuntimeHintsRegistrar="
                            + "zrouga.spring.security.ZrougaRuntimeHints");
        }
    }
}
