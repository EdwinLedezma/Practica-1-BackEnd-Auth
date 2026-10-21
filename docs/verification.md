# Evidencia de verificacion — HU-SEC-001

Verificacion local realizada el 21 de octubre de 2026 con Java 21, Maven 3.9.11 y Spring Boot 3.5.16.

## Suite Java

Comando: `mvnw.cmd -Dmaven.repo.local=.tools/m2 --batch-mode verify`.

Resultado: **BUILD SUCCESS; 10 pruebas, 0 fallos, 0 errores, 0 omitidas**.

Las pruebas arrancan Tomcat con HTTPS real y certificado temporal, sin desactivar la comprobacion de confianza ni del hostname.

## Aplicacion empaquetada

Comando: `python scripts/verify_https.py --wait 60`, contra `java -jar target/backend-auth-1.0.0.jar`.

```text
PASS: HTTPS con certificado y hostname verificados
PASS: negociacion TLSv1_2
PASS: negociacion TLSv1_3
PASS: TLS_HANDSHAKE_REJECTED - protocolo no permitido: TLSv1
PASS: TLS_HANDSHAKE_REJECTED - protocolo no permitido: TLSv1_1
PASS: TLS_CERTIFICATE_UNTRUSTED - importa el certificado local o utiliza --cacert
PASS: HTTP sin cifrar rechazado con 400 en puerto HTTPS
PASS: login JWT, 401, acceso autenticado y permisos USER/ADMIN (403/200)
```

Los logs de Tomcat confirmaron `SSLHandshakeException` con `protocol_version` para TLSv1 y TLSv1.1. Los logs de la aplicacion registraron `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `UNAUTHORIZED` y `FORBIDDEN`.

## curl

`curl.exe --cacert .local/localhost.crt --tlsv1.2 --tls-max 1.2 https://localhost:8443/api/auth/health` devolvio **HTTP 200** y `{"status":"UP"}`.

`curl.exe --cacert .local/localhost.crt https://localhost:8443/api/me` sin token devolvio **HTTP 401** y el JSON personalizado con codigo `UNAUTHORIZED`.

## Criterios de aceptacion

| Criterio | Implementacion y evidencia |
| --- | --- |
| Keystore/certificado | Scripts keytool, PKCS12 y SAN localhost/127.0.0.1; certificados privados excluidos de Git |
| Solo TLS 1.2/1.3 | application.yml y negociacion real de ambos protocolos; rechazo de 1.0/1.1 |
| HTTP rechazado | Sin conector HTTP adicional; HTTP en 8443 devuelve 400 |
| SecurityFilterChain | Rutas publicas explicitas; el resto exige Bearer JWT |
| Tokens validos | Firma, caducidad, emisor y audiencia probados; rechazo de tokens alterados |
| 401 y 403 | JSON personalizado y pruebas USER/ADMIN |
| Eventos y errores | Eventos sin credenciales; Tomcat registra handshake fallido; cliente muestra mensajes TLS personalizados |

Un handshake fallido no admite una respuesta HTTP/JSON: la conexion segura no se establecio. Esta limitacion del protocolo y el manejo correcto se explican en el README.

GitHub Actions repite la verificacion en Linux en cada push y pull request. Sus resultados se consultan en la pestaña Actions del repositorio; este documento registra la ejecucion local y no sustituye el estado de CI.
