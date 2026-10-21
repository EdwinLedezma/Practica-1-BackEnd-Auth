package mx.edu.utch.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

@Component
public class SecurityErrors {
    private static final Logger log = LoggerFactory.getLogger(SecurityErrors.class);
    private final ObjectMapper mapper;

    public SecurityErrors(ObjectMapper mapper) { this.mapper = mapper; }

    public void unauthorized(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setHeader("WWW-Authenticate", "Bearer");
        write(request, response, 401, "UNAUTHORIZED", "Se requiere autenticacion valida.");
    }

    public void forbidden(HttpServletRequest request, HttpServletResponse response) throws IOException {
        write(request, response, 403, "FORBIDDEN", "No tienes permisos para acceder a este recurso.");
    }

    private void write(HttpServletRequest request, HttpServletResponse response, int status,
                       String code, String message) throws IOException {
        // Never record passwords, Authorization headers, token contents or attacker-controlled paths.
        log.warn("security_event={} status={} remote={}", code, status, request.getRemoteAddr());
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        mapper.writeValue(response.getOutputStream(), ApiError.of(status, code, message, request.getRequestURI()));
    }
}
