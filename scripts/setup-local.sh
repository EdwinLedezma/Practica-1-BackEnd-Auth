#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
umask 077
mkdir -p .local
if [ -e .local/secrets.sh ]; then echo 'Ya existe .local/secrets.sh; cargalo con . ./.local/secrets.sh'; exit 1; fi
export SSL_KEY_STORE_PASSWORD="$(openssl rand -base64 32)"
export JWT_SECRET="$(openssl rand -base64 32)"
export APP_USER_PASSWORD="$(openssl rand -base64 32)"
export APP_ADMIN_PASSWORD="$(openssl rand -base64 32)"
keytool -genkeypair -alias localhost -keyalg RSA -keysize 3072 -sigalg SHA256withRSA -storetype PKCS12 -keystore .local/localhost.p12 -storepass:env SSL_KEY_STORE_PASSWORD -validity 365 -dname 'CN=localhost,OU=Desarrollo,O=UTCH,L=Chihuahua,ST=Chihuahua,C=MX' -ext 'SAN=dns:localhost,ip:127.0.0.1' -noprompt
keytool -exportcert -rfc -alias localhost -keystore .local/localhost.p12 -storepass:env SSL_KEY_STORE_PASSWORD -file .local/localhost.crt
printf "export SSL_KEY_STORE_PASSWORD='%s'\nexport JWT_SECRET='%s'\nexport APP_USER_PASSWORD='%s'\nexport APP_ADMIN_PASSWORD='%s'\n" "$SSL_KEY_STORE_PASSWORD" "$JWT_SECRET" "$APP_USER_PASSWORD" "$APP_ADMIN_PASSWORD" > .local/secrets.sh
echo 'Carga las variables: . ./.local/secrets.sh'
