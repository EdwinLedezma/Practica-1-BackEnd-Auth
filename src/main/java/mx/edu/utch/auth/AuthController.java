package mx.edu.utch.auth;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private final AuthenticationManager manager;
    private final JwtEncoder encoder;
    private final String issuer;
    private final String audience;
    private final Duration ttl;

    public AuthController(AuthenticationManager manager, JwtEncoder encoder,
        @Value("${app.jwt.issuer}") String issuer, @Value("${app.jwt.audience}") String audience,
        @Value("${app.jwt.ttl}") Duration ttl) {
        this.manager = manager; this.encoder = encoder; this.issuer = issuer; this.audience = audience; this.ttl = ttl;
    }

    public record LoginRequest(@NotBlank @Size(max=100) String username,
                               @NotBlank @Size(max=72) String password) {}
    public record TokenResponse(String accessToken, String tokenType, long expiresIn) {}

    @PostMapping("/login")
    ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        var authentication = manager.authenticate(
            UsernamePasswordAuthenticationToken.unauthenticated(request.username(), request.password()));
        Instant now = Instant.now();
        var roles = authentication.getAuthorities().stream().map(a -> a.getAuthority().substring(5)).toList();
        var claims = JwtClaimsSet.builder().issuer(issuer).audience(List.of(audience))
            .subject(authentication.getName()).issuedAt(now).expiresAt(now.plus(ttl)).claim("roles", roles).build();
        String token = encoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims)).getTokenValue();
        log.info("security_event=LOGIN_SUCCESS");
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
            .body(new TokenResponse(token, "Bearer", ttl.toSeconds()));
    }

    @GetMapping("/health") Map<String, String> health() { return Map.of("status", "UP"); }
}
