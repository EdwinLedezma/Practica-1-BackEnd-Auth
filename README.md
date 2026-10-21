# Practica 1 BackEnd Auth

HU-SEC-001: autenticación con Spring Security y cifrado TLS/SSL en Java.

Implementación individual de autenticación y autorización para un API Java con Spring Boot 3.5.16, Spring Security, JWT firmado con HS256 y HTTPS en el puerto **8443**.

## Requisitos

JDK 21, acceso a Maven Central para descargar dependencias y Python 3.10+ para la verificación adicional. Maven se descarga mediante el wrapper incluido. En Linux/macOS se necesita OpenSSL para generar secretos de desarrollo.

## Ejecutar en Windows (PowerShell)

```powershell
./scripts/setup-local.ps1
. ./.local/secrets.ps1
./mvnw.cmd verify
./scripts/run-local.ps1
```

En otra terminal, con el servidor activo:

```powershell
. ./.local/secrets.ps1
python ./scripts/verify_https.py
```

`setup-local.ps1` usa `keytool` para generar una clave RSA de 3072 bits, un keystore PKCS12 y un certificado autofirmado con SAN `localhost` y `127.0.0.1`, válido por 365 días. Genera cuatro secretos aleatorios de 32 bytes. Guarda el certificado en `.local/localhost.crt`, el keystore en `.local/localhost.p12` y las variables en `.local/secrets.ps1`. Ese archivo contiene las contraseñas de los usuarios de demostración `user` y `admin`; no lo publiques. El script evita sobrescribir una configuración existente.

Si Java no está en PATH y existe un JDK local en `.tools/jdk-*`, los scripts PowerShell lo detectan. En una instalación normal, configura `JAVA_HOME` y PATH antes de ejecutar el wrapper.

## Ejecutar en Linux/macOS

```sh
sh scripts/setup-local.sh
. ./.local/secrets.sh
sh mvnw verify
sh mvnw spring-boot:run
# En otra terminal:
. ./.local/secrets.sh
python3 scripts/verify_https.py
```

## Rutas y pruebas con curl

| Método | Ruta | Acceso |
| --- | --- | --- |
| GET | `/api/auth/health` | Público, responde `UP` |
| POST | `/api/auth/login` | Público, autentica username/password |
| GET | `/api/me` | JWT válido, USER o ADMIN |
| GET | `/api/admin/dashboard` | JWT válido con rol ADMIN |

Ejemplo PowerShell, sin desactivar la verificación del certificado:

```powershell
. ./.local/secrets.ps1
curl.exe --cacert .local/localhost.crt --tlsv1.2 --tls-max 1.2 https://localhost:8443/api/auth/health
curl.exe --cacert .local/localhost.crt --tlsv1.3 --tls-max 1.3 https://localhost:8443/api/auth/health
curl.exe --cacert .local/localhost.crt -i https://localhost:8443/api/me

$body = @{ username = 'user'; password = $env:APP_USER_PASSWORD } | ConvertTo-Json
# curl con archivo evita problemas de comillas JSON entre versiones de PowerShell.
$body | Set-Content .local/login.json -Encoding ascii
$login = curl.exe --silent --show-error --cacert .local/localhost.crt -H 'Content-Type: application/json' --data-binary '@.local/login.json' https://localhost:8443/api/auth/login | ConvertFrom-Json
curl.exe --cacert .local/localhost.crt -i -H "Authorization: Bearer $($login.accessToken)" https://localhost:8443/api/me
curl.exe --cacert .local/localhost.crt -i -H "Authorization: Bearer $($login.accessToken)" https://localhost:8443/api/admin/dashboard
curl.exe -i http://localhost:8443/api/auth/health
```

Resultados: HTTPS 200; petición sin token 401; `/api/me` con token 200; `user` en ruta administrativa 403; HTTP en el puerto TLS 400. Repite el login con `admin` y `APP_ADMIN_PASSWORD` para obtener 200 en la ruta administrativa. No se abre un conector HTTP en 8080. TLS 1.0 y 1.1 se rechazan. Algunos builds de curl para Windows no permiten forzar TLS 1.3; el script Python y las pruebas Java verifican ambos protocolos independientemente.

En Postman importa `.local/localhost.crt` como certificado de confianza, envía el JSON a `/api/auth/login` y usa `accessToken` como Bearer Token. Usa siempre `https://localhost:8443`.

## Seguridad y configuración

La cadena `SecurityFilterChain` protege por defecto todas las rutas salvo dos rutas públicas explícitas. La API no utiliza sesión, cookies, Basic Auth ni formulario de login. BCrypt (coste 12) almacena en memoria hashes de las contraseñas configuradas. Los usuarios son de demostración y no hay registro, persistencia ni recuperación de contraseña.

JWT tiene duración de 15 minutos. Se validan firma HS256, caducidad sin tolerancia adicional, emisor `backend-auth` y audiencia `backend-api`. La respuesta del login incluye `accessToken`, `tokenType` y `expiresIn`, con `Cache-Control: no-store`. Los roles se obtienen de los usuarios autenticados, nunca del cuerpo de la petición. Para esta práctica no hay refresh tokens ni revocación: el token sigue siendo válido hasta caducar; cambiar la clave invalida todos los tokens anteriores.

CSRF está deshabilitado porque se utiliza exclusivamente el encabezado Authorization con Bearer Token, sin credenciales automáticas del navegador. CORS permite por defecto `https://localhost:4200` y los encabezados Authorization/Content-Type. Configura orígenes explícitos separados por comas mediante `CORS_ALLOWED_ORIGINS`; para una demostración con Angular HTTP puedes agregar `http://localhost:4200`, aunque para cifrado de extremo a extremo debes servir también Angular por HTTPS.

Variables obligatorias: `SSL_KEY_STORE_PASSWORD`, `JWT_SECRET` (Base64, mínimo 32 bytes decodificados), `APP_USER_PASSWORD` y `APP_ADMIN_PASSWORD` (mínimo 12 caracteres). Sin ellas la aplicación falla al iniciar. `SSL_KEY_STORE` permite importar otro PKCS12 con alias `localhost`. `.local/`, `.tools/`, `.env`, keystores y logs quedan excluidos de Git. Nunca uses los secretos de desarrollo en producción.

Para producción importa un certificado emitido por una CA confiable, restringe los archivos secretos al usuario del servicio y usa un gestor de secretos. La práctica no implementa límites de intentos de login; un despliegue público requiere esa protección y un almacén de usuarios persistente.

## Errores y eventos

Los errores de autenticación y autorización devuelven JSON con `timestamp`, `status`, `code`, `message` y `path`: `INVALID_CREDENTIALS` (401), `UNAUTHORIZED` (401), `FORBIDDEN` (403), `INVALID_REQUEST` (400). No exponen contraseñas, tokens ni stack traces.

Se registran eventos `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `UNAUTHORIZED` y `FORBIDDEN` sin contraseñas ni tokens. Tomcat registra fallos de handshake TLS mediante el nivel DEBUG de `org.apache.tomcat.util.net`, configurado para la demostración; puede contener detalles internos de red, por lo que debe ajustarse y restringirse su acceso en producción.

Un handshake TLS fallido ocurre **antes de HTTP**: el servidor no puede devolver un mensaje JSON a través de una conexión que no se estableció. El cliente recibe la alerta TLS; `verify_https.py` la traduce a mensajes personalizados `TLS_HANDSHAKE_REJECTED` y `TLS_CERTIFICATE_UNTRUSTED`. Los errores HTTP de autenticación sí son personalizados por Spring. La aplicación no intercepta fallos TLS con un `@ControllerAdvice` porque técnicamente no pasan por los controladores.

## Verificación automatizada

`./mvnw.cmd verify` (Windows) o `sh mvnw verify` (Linux/macOS) arranca un servidor HTTPS en un puerto aleatorio y crea un certificado temporal en `target/`. No requiere secretos del desarrollador. Comprueba login, 400/401/403, roles, firma alterada, token malformado o vencido, emisor y audiencia incorrectos, CORS, HSTS, ausencia de sesión, confianza del certificado, TLS 1.2/1.3 y rechazo de HTTP.

`python scripts/verify_https.py` añade pruebas contra la aplicación empaquetada, incluyendo ofertas reales de TLS 1.0/1.1 desde el cliente. Usa el certificado local como CA de confianza y también comprueba que el cliente rechace un certificado no confiable. GitHub Actions ejecuta ambas suites y conserva los reportes JUnit como artefactos.

## Flujo Git

Repositorio: [Practica-1-BackEnd-Auth](https://github.com/EdwinLedezma/Practica-1-BackEnd-Auth).

Ramas: `main`, `develop` y `feature/backend-auth-tls`. El desarrollo se realiza en la feature. La entrega se integra mediante **squash merge a develop**, seguido de **squash merge de develop a main**. `main` es la rama final; se usan los nombres main/develop pedidos al inicio de la actividad.

## Referencias

- [Spring Boot: configuración SSL](https://docs.spring.io/spring-boot/3.5/how-to/webserver.html#howto.webserver.configure-ssl)
- [Spring Security: validación JWT](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html)
