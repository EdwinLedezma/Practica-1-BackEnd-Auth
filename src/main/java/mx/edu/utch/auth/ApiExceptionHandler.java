package mx.edu.utch.auth;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApiExceptionHandler {
    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(AuthenticationException.class)
    ResponseEntity<ApiError> authentication(HttpServletRequest request) {
        log.warn("security_event=LOGIN_FAILURE remote={}", request.getRemoteAddr());
        return ResponseEntity.status(401).header("WWW-Authenticate", "Bearer")
            .body(ApiError.of(401, "INVALID_CREDENTIALS", "Usuario o contrasena incorrectos.", request.getRequestURI()));
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, HttpMessageNotReadableException.class})
    ResponseEntity<ApiError> validation(HttpServletRequest request) {
        return ResponseEntity.badRequest().body(ApiError.of(400, "INVALID_REQUEST",
            "Envia un JSON valido con username y password no vacios.", request.getRequestURI()));
    }
}
