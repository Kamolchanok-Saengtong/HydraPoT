"""
console/tls.py — HTTPS for the operator console.

WHY. The login and the session cookie are the two most sensitive things the
dashboard sends, and over plain HTTP both are readable by anyone on the path:
a compromised access point, a switch doing port mirroring, a host doing ARP
spoofing on the same LAN. The cookie matters as much as the password, because
replaying it skips the login entirely.

THE SSH TUNNEL IS STILL THE STRONGER ANSWER and still the default, because it
encrypts the same traffic AND leaves nothing listening on the network to
attack. This file is for the case where a browser should reach the dashboard
directly -- several analysts, a jump host, a reverse proxy -- and the choice is
then between TLS and clear text, not between TLS and a tunnel.

SELF-SIGNED IS NOT A DOWNGRADE HERE, with one caveat. Against a passive
eavesdropper -- which is the threat above -- a self-signed certificate gives
exactly the same encryption as a paid one. What it does not give is proof of
identity: the first time a browser sees it you get a warning, and you cannot
distinguish the real certificate from an attacker's substitute unless you
check the fingerprint. So fingerprint() is printed on generation: compare it
once in the browser, and from then on a changed fingerprint means something is
wrong.

For a deployment where that is not good enough, point cert_file/key_file at a
real certificate (Let's Encrypt, or your organisation's CA) and nothing else
changes.
"""
import datetime
import hashlib
import ipaddress
import os
import socket

from core.config_loader import load_config

_HERE = os.path.abspath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".."))
_CONFIG_PATH = os.path.join(_HERE, "config.yaml")

# Browsers reject a leaf certificate valid for much longer than this, and
# Apple's limit is the strictest at 825 days. Self-signed certificates added
# to a trust store are not strictly bound by it, but matching the rule keeps
# the same file usable when it is later served through a proxy.
VALID_DAYS = 825


# Env overrides for the two paths, same convention as console/auth.py: a
# container mounts its certificate where it likes, and the tests need a temp
# directory. A real environment variable wins, as everywhere else in HydraPoT.
ENV_CERT = "HYDRAPOT_DASHBOARD_CERT"
ENV_KEY = "HYDRAPOT_DASHBOARD_KEY"


def cfg():
    return load_config(_CONFIG_PATH).dashboard.tls


def _abs(path: str) -> str:
    return path if os.path.isabs(path) else os.path.join(_HERE, path)


def cert_path() -> str:
    return _abs(os.environ.get(ENV_CERT) or cfg().cert_file)


def key_path() -> str:
    return _abs(os.environ.get(ENV_KEY) or cfg().key_file)


def exists() -> bool:
    return os.path.exists(cert_path()) and os.path.exists(key_path())


def _san_entries(extra_host: str = ""):
    """Names and addresses the certificate should be valid for.

    A certificate is checked against the name in the URL, so one valid only
    for "localhost" produces a warning the moment you reach the dashboard by
    IP -- which is the whole point of turning TLS on. Collect every way this
    machine is legitimately addressed.
    """
    from cryptography import x509

    names, addresses = {"localhost"}, {"127.0.0.1", "::1"}
    try:
        hostname = socket.gethostname()
        if hostname:
            names.add(hostname)
            fqdn = socket.getfqdn()
            if fqdn:
                names.add(fqdn)
    except OSError:
        pass

    # The address hp.py will actually bind. 0.0.0.0 is not a name a browser
    # ever connects to, so it is recorded as the local addresses instead.
    host = (extra_host or "").strip()
    if host and host not in ("0.0.0.0", "::", ""):
        try:
            addresses.add(str(ipaddress.ip_address(host)))
        except ValueError:
            names.add(host)
    if host in ("0.0.0.0", "::"):
        try:
            addresses.add(socket.gethostbyname(socket.gethostname()))
        except OSError:
            pass

    entries = [x509.DNSName(n) for n in sorted(names)]
    for a in sorted(addresses):
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(a)))
        except ValueError:
            pass
    return entries


def generate(bind_host: str = "", force: bool = False) -> tuple:
    """Write a self-signed certificate and key. Returns (cert, key, names).

    The key is created 0600 before any bytes are written -- not chmod'd
    afterwards, which would leave the private key briefly world-readable.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    cert_file, key_file = cert_path(), key_path()
    if exists() and not force:
        raise FileExistsError(
            f"{cert_file} already exists; pass force=True to replace it")

    for path in (cert_file, key_file):
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    # P-256 rather than RSA-2048: same practical strength, a much smaller key,
    # and a faster handshake. Every current browser has supported it for years.
    key = ec.generate_private_key(ec.SECP256R1())
    sans = _san_entries(bind_host)
    # The CN is legacy -- browsers have read only the SAN list since 2017 --
    # but tools that print a certificate still show it, so make it say what
    # this is rather than leaving it blank.
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "HydraPoT dashboard"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HydraPoT"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)                     # self-signed: issuer == subject
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        # A minute in the past: a client whose clock is slightly behind would
        # otherwise reject a certificate generated seconds ago.
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=False,
            content_commitment=False, data_encipherment=False,
            key_agreement=True, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage(
            [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )

    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
    # No passphrase: uvicorn would have to be given it at every start, so it
    # would end up in config.yaml or a systemd unit next to the key itself.
    # 0600 is the protection.

    with open(cert_file, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))

    return cert_file, key_file, [str(getattr(s, "value", s)) for s in sans]


def fingerprint() -> str:
    """SHA-256 of the certificate, grouped like a browser shows it.

    This is what makes a self-signed certificate trustworthy in practice:
    compare it once against what the browser reports, and a later change means
    you are not talking to the same server.
    """
    with open(cert_path(), "rb") as fh:
        pem = fh.read()
    # Strip the PEM armour to hash the DER bytes, which is what every tool
    # fingerprints -- hashing the PEM text gives a different, useless value.
    import base64
    body = b"".join(line for line in pem.splitlines()
                    if b"-----" not in line)
    digest = hashlib.sha256(base64.b64decode(body)).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def expires_in_days() -> int:
    from cryptography import x509
    with open(cert_path(), "rb") as fh:
        cert = x509.load_pem_x509_certificate(fh.read())
    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:                 # cryptography < 42
        not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    return (not_after - datetime.datetime.now(datetime.timezone.utc)).days


def uvicorn_kwargs() -> dict:
    """ssl_* arguments for uvicorn.run, or {} when TLS is off.

    Returning the kwargs rather than having hp.py build them keeps the
    "is TLS on, and where are its files" question in one place.
    """
    c = cfg()
    if not c.enabled:
        return {}
    return {"ssl_certfile": cert_path(), "ssl_keyfile": key_path()}
