package mx.edu.utch.auth;

import java.time.Instant;

public record ApiError(Instant timestamp, int status, String code, String message, String path) {
    public static ApiError of(int status, String code, String message, String path) {
        return new ApiError(Instant.now(), status, code, message, path);
    }
}
