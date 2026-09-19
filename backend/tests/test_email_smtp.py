"""Proves app.notifications.email.send_email really sends mail over a real
SMTP+STARTTLS connection (the real aiosmtplib code path) — not just the
log-fallback path this module falls back to when SMTP isn't configured or
a send fails. Runs a real local SMTP server (aiosmtpd) with a real,
ephemerally-generated self-signed TLS certificate; nothing here is mocked
except the certificate-trust step a real deployment would instead get from
its OS/CA trust store recognizing its mail provider's real certificate.
"""
import datetime
import ipaddress
import socket
import ssl

import pytest
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.config import get_settings


def _generate_self_signed_cert(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=5))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(minutes=30))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path = tmp_path / "smtp_key.pem"
    cert_path = tmp_path / "smtp_cert.pem"
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(cert_path), str(key_path)


class _CapturingHandler(Message):
    def __init__(self):
        super().__init__()
        self.received = []

    def handle_message(self, message):
        self.received.append(message)


@pytest.fixture
def real_smtp_server(tmp_path):
    """A real SMTP server accepting STARTTLS on localhost, real cert and
    all — not a mock of aiosmtplib or of the network call."""
    cert_path, key_path = _generate_self_signed_cert(tmp_path)
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(cert_path, key_path)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        free_port = probe.getsockname()[1]

    handler = _CapturingHandler()
    controller = Controller(handler, hostname="127.0.0.1", port=free_port, tls_context=tls_context)
    controller.start()
    try:
        yield controller, handler
    finally:
        controller.stop()


@pytest.fixture
def configured_smtp(monkeypatch, real_smtp_server):
    controller, handler = real_smtp_server
    settings = get_settings()
    monkeypatch.setattr(settings, "smtp_host", "127.0.0.1")
    monkeypatch.setattr(settings, "smtp_port", controller.port)
    monkeypatch.setattr(settings, "smtp_username", None)
    monkeypatch.setattr(settings, "smtp_password", None)
    monkeypatch.setattr(settings, "smtp_from", "alerts@sentrimeshastra.local")
    monkeypatch.setattr(settings, "notify_to_email", "soc-team@customer.example")

    # A self-signed test cert has no real CA behind it; a production
    # deployment instead gets a certificate its OS trust store already
    # recognizes (Let's Encrypt, the mail provider's own CA, etc.) — this
    # patch stands in for that, not for the STARTTLS handshake or send
    # itself, which both run for real against the real server above.
    import aiosmtplib

    orig_send = aiosmtplib.send

    async def patched_send(*args, **kwargs):
        kwargs["validate_certs"] = False
        return await orig_send(*args, **kwargs)

    monkeypatch.setattr(aiosmtplib, "send", patched_send)
    return handler


async def test_send_email_delivers_via_real_smtp_starttls(configured_smtp):
    from app.notifications.email import send_email

    handler = configured_smtp
    ok = await send_email("Test Incident Alert", "A brute-force incident was opened for 203.0.113.5.")
    assert ok is True

    assert len(handler.received) == 1
    msg = handler.received[0]
    assert msg["From"] == "alerts@sentrimeshastra.local"
    assert msg["To"] == "soc-team@customer.example"
    assert msg["Subject"] == "[SentriMeshAstra] Test Incident Alert"
    assert msg.get_payload(decode=True).decode().strip() == "A brute-force incident was opened for 203.0.113.5."


async def test_send_email_honors_explicit_recipient_override(configured_smtp):
    from app.notifications.email import send_email

    handler = configured_smtp
    ok = await send_email("Direct alert", "body", to="on-call@customer.example")
    assert ok is True
    assert handler.received[0]["To"] == "on-call@customer.example"


async def test_send_email_falls_back_gracefully_when_smtp_unreachable(monkeypatch):
    """A real connection failure (nothing listening on that port) must be
    caught, not raised — the caller (Response agent) never crashes just
    because a customer's SMTP relay is briefly unreachable."""
    settings = get_settings()
    monkeypatch.setattr(settings, "smtp_host", "127.0.0.1")
    monkeypatch.setattr(settings, "smtp_port", 1)  # nothing listens on port 1
    monkeypatch.setattr(settings, "notify_to_email", "soc-team@customer.example")

    from app.notifications.email import send_email

    ok = await send_email("Subject", "body")
    assert ok is False


async def test_send_email_logs_instead_of_sending_when_unconfigured(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "smtp_host", None)
    monkeypatch.setattr(settings, "notify_to_email", "soc-team@customer.example")

    from app.notifications.email import send_email

    ok = await send_email("Subject", "body")
    assert ok is False
