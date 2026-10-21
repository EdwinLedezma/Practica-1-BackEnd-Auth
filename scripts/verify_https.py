"""End-to-end checks using a trusted local certificate; Python 3.10+, no packages."""
import argparse
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import time
import warnings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--wait', type=int, default=0)
    parser.add_argument('--port', type=int, default=8443)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    context = ssl.create_default_context(cafile=str(root / '.local/localhost.crt'))

    def request(method, path, data=None, token=None, ctx=context):
        connection = http.client.HTTPSConnection('localhost', args.port, context=ctx, timeout=5)
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        try:
            connection.request(method, path, json.dumps(data) if data else None, headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    deadline = time.monotonic() + args.wait
    while True:
        try:
            assert request('GET', '/api/auth/health')[0] == 200
            break
        except (OSError, AssertionError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)
    print('PASS: HTTPS con certificado y hostname verificados')
    for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
        ctx = ssl.create_default_context(cafile=str(root / '.local/localhost.crt'))
        ctx.minimum_version = ctx.maximum_version = version
        assert request('GET', '/api/auth/health', ctx=ctx)[0] == 200
        print('PASS: negociacion ' + version.name)

    for version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
        ctx = ssl.create_default_context(cafile=str(root / '.local/localhost.crt'))
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', DeprecationWarning)
            ctx.minimum_version = ctx.maximum_version = version
        # Allow the client to offer legacy protocols so rejection comes from the server.
        ctx.set_ciphers('ALL:@SECLEVEL=0')
        try:
            with socket.create_connection(('localhost', args.port), timeout=5) as raw:
                with ctx.wrap_socket(raw, server_hostname='localhost'):
                    raise AssertionError('El servidor acepto ' + version.name)
        except ssl.SSLError as error:
            assert error.reason in {'TLSV1_ALERT_PROTOCOL_VERSION', 'SSLV3_ALERT_HANDSHAKE_FAILURE',
                                    'UNSUPPORTED_PROTOCOL'}, str(error)
            print('PASS: TLS_HANDSHAKE_REJECTED - protocolo no permitido: ' + version.name)

    try:
        request('GET', '/api/auth/health', ctx=ssl.create_default_context())
        raise AssertionError('Se acepto un certificado no confiable')
    except ssl.SSLCertVerificationError:
        print('PASS: TLS_CERTIFICATE_UNTRUSTED - importa el certificado local o utiliza --cacert')

    with socket.create_connection(('localhost', args.port), timeout=5) as plain:
        plain.sendall(b'GET /api/auth/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
        assert b'400' in plain.recv(4096)
    print('PASS: HTTP sin cifrar rechazado con 400 en puerto HTTPS')
    assert request('GET', '/api/me')[0] == 401
    assert request('GET', '/api/me', token='invalid-token')[0] == 401
    assert request('POST', '/api/auth/login', {'username': 'user', 'password': 'wrong'})[0] == 401
    for username in ('user', 'admin'):
        password = os.environ['APP_' + username.upper() + '_PASSWORD']
        status, body = request('POST', '/api/auth/login', {'username': username, 'password': password})
        assert status == 200
        token = body['accessToken']
        assert request('GET', '/api/me', token=token)[0] == 200
        expected = 200 if username == 'admin' else 403
        assert request('GET', '/api/admin/dashboard', token=token)[0] == expected
    print('PASS: login JWT, 401, acceso autenticado y permisos USER/ADMIN (403/200)')


if __name__ == '__main__':
    main()
