package mx.edu.utch.auth;

import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {
    @GetMapping("/api/me")
    Map<String, Object> me(Authentication auth) {
        return Map.of("username", auth.getName(), "authorities", auth.getAuthorities());
    }

    @GetMapping("/api/admin/dashboard")
    Map<String, String> admin() { return Map.of("message", "Acceso autorizado para ADMIN."); }
}
