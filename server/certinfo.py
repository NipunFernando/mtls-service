"""Turning `ssl` certificate structures into something readable in JSON.

`ssl.SSLSocket.getpeercert()` hands back nested tuples; everything here exists
to flatten those into the strings the /info contract promises.  Stdlib only --
no `cryptography` dependency -- because the whole point of the exercise is to
show what the TLS layer itself can see.
"""

from __future__ import annotations

import hashlib
import ssl

# Short forms for the RDN types OpenSSL emits, so subjects read like the
# familiar "C=LK, O=WSO2, CN=mtls-demo-client".
_RDN_SHORT = {
    "countryName": "C",
    "stateOrProvinceName": "ST",
    "localityName": "L",
    "organizationName": "O",
    "organizationalUnitName": "OU",
    "commonName": "CN",
    "emailAddress": "emailAddress",
    "serialNumber": "serialNumber",
    "domainComponent": "DC",
}


def format_name(name: tuple | None) -> str | None:
    """Flatten a getpeercert() subject/issuer tuple into an RFC 4514-ish string."""
    if not name:
        return None
    parts = []
    for rdn in name:
        for attr, value in rdn:
            parts.append(f"{_RDN_SHORT.get(attr, attr)}={value}")
    return ", ".join(parts)


def fingerprint_sha256(der: bytes | None) -> str | None:
    """Colon-separated uppercase SHA-256, matching `openssl x509 -fingerprint`."""
    if not der:
        return None
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def subject_alt_names(cert: dict) -> list[str]:
    return [f"{kind}:{value}" for kind, value in cert.get("subjectAltName", ())]


def peer_summary(cert: dict | None, der: bytes | None) -> dict:
    """The `mtls` block of /info, built purely from what the handshake produced."""
    if not cert:
        # Unreachable while verify_mode is CERT_REQUIRED, but /info should still
        # describe reality rather than assume it.
        return {
            "client_cert_present": False,
            "note": "no client certificate was presented",
        }
    return {
        "client_cert_present": True,
        "subject": format_name(cert.get("subject")),
        "issuer": format_name(cert.get("issuer")),
        "serial": cert.get("serialNumber"),
        "version": cert.get("version"),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "subject_alt_names": subject_alt_names(cert),
        "sha256_fingerprint": fingerprint_sha256(der),
    }


def decode_cert_file(path: str) -> dict:
    """Describe a PEM certificate on disk (used for the server's own cert).

    `ssl._ssl._test_decode_cert` is private, but it is the only stdlib route to
    a parsed certificate that is not attached to a live socket.  If a future
    Python drops it we degrade to reporting the fingerprint alone rather than
    failing the request.
    """
    summary: dict = {"path": path}
    try:
        with open(path, "rb") as handle:
            pem = handle.read().decode("utf-8")
        der = ssl.PEM_cert_to_DER_cert(pem)
        summary["sha256_fingerprint"] = fingerprint_sha256(der)
    except (OSError, ValueError) as exc:
        summary["error"] = f"could not read certificate: {exc}"
        return summary

    try:
        cert = ssl._ssl._test_decode_cert(path)  # noqa: SLF001 - see docstring
    except (AttributeError, ssl.SSLError, OSError) as exc:
        summary["subject"] = "unavailable"
        summary["issuer"] = "unavailable"
        summary["note"] = f"certificate parsing unavailable on this runtime: {exc}"
        return summary

    summary.update(
        {
            "subject": format_name(cert.get("subject")),
            "issuer": format_name(cert.get("issuer")),
            "serial": cert.get("serialNumber"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "subject_alt_names": subject_alt_names(cert),
        }
    )
    return summary
