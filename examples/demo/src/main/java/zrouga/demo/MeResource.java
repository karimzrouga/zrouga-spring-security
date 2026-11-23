package zrouga.demo;

import java.util.Map;

import zrouga.spring.security.UserDetailsImpl;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoint protégé : n'importe quel utilisateur authentifié (JWT valide) peut l'appeler.
 */
@RestController
@RequestMapping("/api")
public class MeResource {

    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public Map<String, Object> me(@AuthenticationPrincipal UserDetailsImpl user) {
        return Map.of(
                "id", user.getId(),
                "email", user.getEmail(),
                "roles", user.getRoles());
    }
}
