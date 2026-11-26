package zrouga.spring.security;

import java.util.List;

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

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;

/**
 * Registre de {@code RuntimeHints} pour les images natives GraalVM :
 * les DTO (records) sont sérialisés par Jackson en réflexion.
 */
public class ZrougaRuntimeHints implements RuntimeHintsRegistrar {

    private static final List<Class<?>> SERIALIZED_TYPES = List.of(
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

    @Override
    public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
        for (Class<?> type : SERIALIZED_TYPES) {
            hints.reflection().registerType(type, MemberCategory.values());
        }
    }
}
