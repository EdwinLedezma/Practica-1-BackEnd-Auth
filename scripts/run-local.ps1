$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not (Test-Path .local/secrets.ps1)) { & ./scripts/setup-local.ps1 }
. ./.local/secrets.ps1
if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    $localJdk = Get-ChildItem .tools -Directory -Filter 'jdk-*' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $localJdk) { throw 'Instala JDK 21 y configura JAVA_HOME.' }
    $env:JAVA_HOME = $localJdk.FullName
    $env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
}
& ./mvnw.cmd spring-boot:run
if ($LASTEXITCODE -ne 0) { throw 'No se pudo iniciar el backend.' }
