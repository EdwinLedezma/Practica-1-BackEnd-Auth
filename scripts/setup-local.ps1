$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not (Get-Command keytool -ErrorAction SilentlyContinue)) {
    $localJdk = Get-ChildItem .tools -Directory -Filter 'jdk-*' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $localJdk) { throw 'Instala JDK 21 y agrega su carpeta bin al PATH.' }
    $env:JAVA_HOME = $localJdk.FullName
    $env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
}
New-Item -ItemType Directory -Force .local | Out-Null
if (Test-Path .local/secrets.ps1) { throw 'Ya existe .local/secrets.ps1. Cargalo con: . ./.local/secrets.ps1' }
function New-Secret {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    [Convert]::ToBase64String($bytes)
}
$env:SSL_KEY_STORE_PASSWORD = New-Secret
$env:JWT_SECRET = New-Secret
$env:APP_USER_PASSWORD = New-Secret
$env:APP_ADMIN_PASSWORD = New-Secret
& keytool -genkeypair -alias localhost -keyalg RSA -keysize 3072 -sigalg SHA256withRSA -storetype PKCS12 -keystore .local/localhost.p12 -storepass:env SSL_KEY_STORE_PASSWORD -validity 365 -dname 'CN=localhost,OU=Desarrollo,O=UTCH,L=Chihuahua,ST=Chihuahua,C=MX' -ext 'SAN=dns:localhost,ip:127.0.0.1' -noprompt
if ($LASTEXITCODE -ne 0) { throw 'No se pudo generar el keystore.' }
& keytool -exportcert -rfc -alias localhost -keystore .local/localhost.p12 -storepass:env SSL_KEY_STORE_PASSWORD -file .local/localhost.crt
if ($LASTEXITCODE -ne 0) { throw 'No se pudo exportar el certificado.' }
$lines = foreach ($name in @('SSL_KEY_STORE_PASSWORD','JWT_SECRET','APP_USER_PASSWORD','APP_ADMIN_PASSWORD')) {
    '$env:' + $name + " = '" + [Environment]::GetEnvironmentVariable($name) + "'"
}
$lines | Set-Content .local/secrets.ps1 -Encoding UTF8
Write-Host 'Certificado generado. Carga las variables: . ./.local/secrets.ps1'
Write-Host 'Las contrasenas para la demostracion estan en .local/secrets.ps1 (ignorado por Git).'
