package mx.edu.utch.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.Socket;
import java.net.http.*;
import java.nio.file.*;
import java.security.KeyStore;
import java.time.Instant;
import java.util.List;
import javax.net.ssl.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import static org.assertj.core.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SecurityIntegrationTest {
    private static final String PASSWORD = "integration-test-password";
    private static SSLContext context;
    private static HttpClient client;
    @LocalServerPort int port;
    @Autowired ObjectMapper mapper;
    @Autowired JwtEncoder encoder;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) throws Exception {
        Path store = Path.of("target", "test-tls.p12").toAbsolutePath();
        Files.createDirectories(store.getParent());
        Files.deleteIfExists(store);
        String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        Process process = new ProcessBuilder(keytool, "-genkeypair", "-alias", "localhost", "-keyalg", "RSA",
            "-storetype", "PKCS12", "-keystore", store.toString(), "-storepass", PASSWORD,
            "-validity", "1", "-dname", "CN=localhost", "-ext", "SAN=dns:localhost,ip:127.0.0.1", "-noprompt")
            .redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes());
        if (process.waitFor() != 0) throw new IllegalStateException(output);
        registry.add("server.ssl.key-store", () -> store.toUri().toString());
        registry.add("server.ssl.key-store-password", () -> PASSWORD);
        registry.add("app.jwt.secret", () -> "dGVzdC1vbmx5LXNlY3JldC13aXRoLTMyaXRlcy1vci1tb3JlISE=");
        registry.add("app.users.user-password", () -> PASSWORD);
        registry.add("app.users.admin-password", () -> PASSWORD);
        var trust = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(store)) { trust.load(input, PASSWORD.toCharArray()); }
        var factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(trust);
        context = SSLContext.getInstance("TLS");
        context.init(null, factory.getTrustManagers(), null);
        client = HttpClient.newBuilder().sslContext(context).build();
    }

    private HttpResponse<String> get(String path, String token) throws Exception {
        var builder = HttpRequest.newBuilder(URI.create("https://localhost:" + port + path));
        if (token != null) builder.header("Authorization", "Bearer " + token);
        return client.send(builder.GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> login(String username, String password) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("https://localhost:" + port + "/api/auth/login"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(
                java.util.Map.of("username", username, "password", password))))
            .build(), HttpResponse.BodyHandlers.ofString());
    }

    private String token(String username) throws Exception {
        var response = login(username, PASSWORD);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("Cache-Control")).contains("no-store");
        return mapper.readTree(response.body()).get("accessToken").asText();
    }

    @Test void healthIsPublicAndProtectedRoutesRequireBearer() throws Exception {
        assertThat(get("/api/auth/health", null).statusCode()).isEqualTo(200);
        var response = get("/api/me", null);
        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(mapper.readTree(response.body()).get("code").asText()).isEqualTo("UNAUTHORIZED");
        assertThat(response.headers().firstValue("WWW-Authenticate")).contains("Bearer");
        assertThat(response.headers().firstValue("Strict-Transport-Security")).isPresent();
        assertThat(response.headers().firstValue("Set-Cookie")).isEmpty();
    }

    @Test void rolesEnforceUserAndAdminAccess() throws Exception {
        String user = token("user");
        assertThat(get("/api/me", user).statusCode()).isEqualTo(200);
        var denied = get("/api/admin/dashboard", user);
        assertThat(denied.statusCode()).isEqualTo(403);
        assertThat(mapper.readTree(denied.body()).get("code").asText()).isEqualTo("FORBIDDEN");
        assertThat(get("/api/admin/dashboard", token("admin")).statusCode()).isEqualTo(200);
    }

    @Test void invalidCredentialsAndInvalidInputReturnSafeErrors() throws Exception {
        var response = login("user", "incorrect-password");
        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(response.body()).doesNotContain("incorrect-password", "stackTrace");
        assertThat(login("", "").statusCode()).isEqualTo(400);
        assertThat(login("unknown", PASSWORD).statusCode()).isEqualTo(401);
    }

    @Test void forgedAndMalformedTokensAreRejected() throws Exception {
        String jwt = token("user");
        String[] parts = jwt.split("\\.");
        String forged = parts[0] + "." + parts[1] + "." + (parts[2].startsWith("A") ? "B" : "A") + parts[2].substring(1);
        assertThat(get("/api/me", forged).statusCode()).isEqualTo(401);
        assertThat(get("/api/me", "not-a-jwt").statusCode()).isEqualTo(401);
    }

    private String signed(Instant expires, String issuer, String audience) {
        var claims = JwtClaimsSet.builder().subject("user").issuer(issuer).audience(List.of(audience))
            .issuedAt(Instant.now().minusSeconds(120)).expiresAt(expires).claim("roles", List.of("USER")).build();
        return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims)).getTokenValue();
    }

    @Test void expiredTokensAndWrongIssuerOrAudienceAreRejected() throws Exception {
        assertThat(get("/api/me", signed(Instant.now().minusSeconds(1), "backend-auth", "backend-api")).statusCode()).isEqualTo(401);
        assertThat(get("/api/me", signed(Instant.now().plusSeconds(120), "wrong", "backend-api")).statusCode()).isEqualTo(401);
        assertThat(get("/api/me", signed(Instant.now().plusSeconds(120), "backend-auth", "wrong")).statusCode()).isEqualTo(401);
    }

    @Test void corsAllowsOnlyConfiguredOrigin() throws Exception {
        for (String origin : List.of("https://localhost:4200", "https://untrusted.example")) {
            var request = HttpRequest.newBuilder(URI.create("https://localhost:" + port + "/api/me"))
                .header("Origin", origin).header("Access-Control-Request-Method", "GET")
                .header("Access-Control-Request-Headers", "Authorization")
                .method("OPTIONS", HttpRequest.BodyPublishers.noBody()).build();
            var response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (origin.contains("localhost")) {
                assertThat(response.statusCode()).isEqualTo(200);
                assertThat(response.headers().firstValue("Access-Control-Allow-Origin")).contains(origin);
            } else {
                assertThat(response.statusCode()).isEqualTo(403);
                assertThat(response.headers().firstValue("Access-Control-Allow-Origin")).isEmpty();
            }
        }
    }

    @ParameterizedTest @ValueSource(strings={"TLSv1.2", "TLSv1.3"})
    void negotiatesOnlyModernTls(String protocol) throws Exception {
        try (SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket("localhost", port)) {
            socket.setEnabledProtocols(new String[]{protocol});
            socket.startHandshake();
            assertThat(socket.getSession().getProtocol()).isEqualTo(protocol);
        }
    }

    @Test void plaintextHttpIsRejected() throws Exception {
        try (var socket = new Socket("localhost", port)) {
            socket.setSoTimeout(5000);
            socket.getOutputStream().write("GET /api/auth/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".getBytes());
            String response = new String(socket.getInputStream().readAllBytes());
            assertThat(response).contains("400").doesNotContain("\"status\":\"UP\"");
        }
    }

    @Test void untrustedCertificateFailsHandshake() {
        var request = HttpRequest.newBuilder(URI.create("https://localhost:" + port + "/api/auth/health")).GET().build();
        assertThatThrownBy(() -> HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString()))
            .isInstanceOf(SSLHandshakeException.class);
    }
}
