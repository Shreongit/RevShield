
import asyncio
import datetime
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)


def create_test_certificates(tmp_path):
    now = datetime.datetime.now(datetime.timezone.utc)

    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    ca_name = x509.Name([
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            "RevShield Test CA",
        )
    ])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )


        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                ca_key.public_key()
            ),
            critical=False,
        )

        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    server_name = x509.Name([
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            "example.com",
        )
    ])

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("example.com")
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_path = tmp_path / "test_ca.pem"
    cert_path = tmp_path / "server.pem"
    key_path = tmp_path / "server.key"

    ca_path.write_bytes(
        ca_cert.public_bytes(x509.Encoding.PEM)
    )
    cert_path.write_bytes(
        server_cert.public_bytes(x509.Encoding.PEM)
    )
    key_path.write_bytes(
        server_key.private_bytes(
            encoding=x509.Encoding.PEM,
            format=x509.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=x509.NoEncryption(),
        )
    )

    return ca_path, cert_path, key_path


def test_real_tls_hostname_verification(tmp_path):
    async def run():
        ca_path, cert_path, key_path = create_test_certificates(
            tmp_path
        )

        server_context = ssl.SSLContext(
            ssl.PROTOCOL_TLS_SERVER
        )
        server_context.load_cert_chain(
            certfile=str(cert_path),
            keyfile=str(key_path),
        )

        async def handle_client(reader, writer):
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(
            handle_client,
            host="127.0.0.1",
            port=0,
            ssl=server_context,
        )

        port = server.sockets[0].getsockname()[1]

        client_context = ssl.create_default_context(
            cafile=str(ca_path)
        )

        assert client_context.verify_mode == ssl.CERT_REQUIRED
        assert client_context.check_hostname is True

        try:
            # Matching hostname must succeed.
            reader, writer = await asyncio.open_connection(
                "127.0.0.1",
                port,
                ssl=client_context,
                server_hostname="example.com",
            )

            assert writer.get_extra_info("ssl_object") is not None

            writer.close()
            await writer.wait_closed()

            # Mismatched hostname must fail.
            try:
                await asyncio.open_connection(
                    "127.0.0.1",
                    port,
                    ssl=client_context,
                    server_hostname="wrong.example.com",
                )
                assert False, "Mismatched certificate was accepted"

            except ssl.SSLCertVerificationError:
                pass

        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(run())
