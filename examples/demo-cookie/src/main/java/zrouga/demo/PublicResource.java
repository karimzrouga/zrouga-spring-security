package zrouga.demo;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoint PUBLIC : déclaré dans {@code zrouga.security.public-paths}
 * ({@code /api/public/**}) — accessible sans jeton.
 */
@RestController
@RequestMapping("/api/public")
public class PublicResource {

    @GetMapping("/hello")
    public Map<String, String> hello() {
        return Map.of("message", "public endpoint - no token required");
    }
}
