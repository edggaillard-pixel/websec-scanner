"""TLS configuration check: certificate validity and accepted protocol versions.

Two independent probes, both read-only:

1. **Certificate** — open a validating TLS connection; on success inspect expiry
   and hostname coverage. On failure, retry without validation to classify the
   problem (expired, self-signed/untrusted, hostname mismatch) from the
   presented certificate.
2. **Protocol versions** — attempt a handshake pinned to TLS 1.0 and TLS 1.1; if
   either succeeds the server accepts an obsolete version.

Only applies to HTTPS targets; plain-HTTP targets yield no findings here (the
lack of HTTPS surfaces through the HSTS/headers checks instead).
"""

from __future__ import annotations

import datetime as dt
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID

from ..core.catalog import make_finding
from ..core.context import ScanContext
from ..core.models import Finding
from ..core.registry import Check, register

_EXPIRY_WARN_DAYS = 21


@register
class TLSCheck(Check):
    id = "tls"
    name = "TLS configuration"
    description = "Validates the certificate and flags obsolete TLS versions."

    def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.is_https:
            return []
        findings: list[Finding] = []
        findings.extend(self._check_certificate(ctx))
        findings.extend(self._check_versions(ctx))
        return findings

    # -- certificate --------------------------------------------------------
    def _check_certificate(self, ctx: ScanContext) -> list[Finding]:
        host, port, timeout = ctx.host, ctx.port, ctx.config.timeout
        # First, a validating handshake to learn whether the chain is trusted.
        trusted_ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with trusted_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    der = ssock.getpeercert(binary_form=True)
            trusted = True
        except ssl.SSLCertVerificationError as exc:
            der, trusted, verify_error = self._grab_cert_insecure(host, port, timeout), False, str(exc)
        except (OSError, ssl.SSLError) as exc:
            ctx.errors.append(f"tls: could not connect to {host}:{port} ({exc})")
            return []

        if der is None:
            return []

        cert = x509.load_der_x509_certificate(der, default_backend())
        findings: list[Finding] = []

        # Expiry
        not_after = cert.not_valid_after_utc
        now = dt.datetime.now(dt.UTC)
        if not_after < now:
            findings.append(
                make_finding(
                    "tls_cert_expired",
                    check=self.id,
                    lang=ctx.lang,
                    not_after=not_after.date().isoformat(),
                    evidence={"not_after": not_after.isoformat()},
                )
            )
        elif (not_after - now).days <= _EXPIRY_WARN_DAYS:
            findings.append(
                make_finding(
                    "tls_cert_expiring_soon",
                    check=self.id,
                    lang=ctx.lang,
                    not_after=not_after.date().isoformat(),
                    days=(not_after - now).days,
                    evidence={"not_after": not_after.isoformat()},
                )
            )

        # Trust + hostname (only when the validating handshake failed)
        if not trusted:
            names = self._san_names(cert)
            if not self._hostname_matches(host, names):
                findings.append(
                    make_finding(
                        "tls_cert_hostname_mismatch",
                        check=self.id,
                        lang=ctx.lang,
                        host=host,
                        names=", ".join(names) or "none",
                        evidence={"host": host, "subjects": names},
                    )
                )
            else:
                findings.append(
                    make_finding(
                        "tls_cert_self_signed",
                        check=self.id,
                        lang=ctx.lang,
                        reason=verify_error.split("(")[0].strip() or "chain not trusted",
                        evidence={"verify_error": verify_error},
                    )
                )
        return findings

    @staticmethod
    def _grab_cert_insecure(host: str, port: int, timeout: float) -> bytes | None:
        insecure = ssl._create_unverified_context()  # noqa: SLF001 - intentional
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with insecure.wrap_socket(sock, server_hostname=host) as ssock:
                    return ssock.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError):
            return None

    @staticmethod
    def _san_names(cert: x509.Certificate) -> list[str]:
        names: list[str] = []
        try:
            ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            names.extend(ext.value.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            pass
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            names.extend(a.value for a in cn)
        except Exception:  # noqa: BLE001
            pass
        return names

    @staticmethod
    def _hostname_matches(host: str, names: list[str]) -> bool:
        host = host.lower()
        for name in names:
            name = name.lower()
            if name == host:
                return True
            if name.startswith("*."):
                suffix = name[1:]  # ".example.com"
                if host.endswith(suffix) and host.count(".") == name.count("."):
                    return True
        return False

    # -- protocol versions --------------------------------------------------
    def _check_versions(self, ctx: ScanContext) -> list[Finding]:
        obsolete: list[str] = []
        for label, maximum in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
            if self._accepts_version(ctx, maximum):
                obsolete.append(label)
        if not obsolete:
            return []
        return [
            make_finding(
                "tls_obsolete_version",
                check=self.id,
                lang=ctx.lang,
                versions=", ".join(obsolete),
                evidence={"accepted": obsolete},
            )
        ]

    @staticmethod
    def _accepts_version(ctx: ScanContext, version: ssl.TLSVersion) -> bool:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = version
            context.maximum_version = version
        except ValueError:
            # This Python/OpenSSL build cannot negotiate that version at all.
            return False
        try:
            with socket.create_connection((ctx.host, ctx.port), timeout=ctx.config.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ctx.host):
                    return True
        except (OSError, ssl.SSLError):
            return False

# GROGNON
