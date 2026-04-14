"""Tests for ssl_cert_scanner script."""

from datetime import datetime, timedelta, timezone

import pytest
from pathlib import Path

from boxctl.core.output import Output


def _openssl_date(dt: datetime) -> str:
    # openssl format: "%b %e %H:%M:%S %Y GMT" (space-padded day). Keep days >= 10
    # so the plain zero-padded output matches openssl's single-space variant.
    return dt.strftime("%b %d %H:%M:%S %Y GMT")


@pytest.fixture
def cert_valid(fixtures_dir):
    """Load valid certificate openssl output."""
    return (fixtures_dir / "security" / "openssl_cert_valid.txt").read_text()


@pytest.fixture
def cert_expiring(fixtures_dir):
    """Load expiring-soon cert with notAfter re-templated to ~20 days from now."""
    text = (fixtures_dir / "security" / "openssl_cert_expiring_soon.txt").read_text()
    now = datetime.now(timezone.utc)
    not_before = _openssl_date(now - timedelta(days=40))
    not_after = _openssl_date(now + timedelta(days=20))
    return (
        text.replace("Jan 15 00:00:00 2026 GMT", not_before)
            .replace("Feb 20 23:59:59 2026 GMT", not_after)
    )


@pytest.fixture
def cert_expired(fixtures_dir):
    """Load expired certificate openssl output."""
    return (fixtures_dir / "security" / "openssl_cert_expired.txt").read_text()


@pytest.fixture
def cert_not_cert(fixtures_dir):
    """Load non-certificate file openssl output."""
    return (fixtures_dir / "security" / "openssl_cert_not_cert.txt").read_text()


class TestSSLCertScanner:
    """Tests for ssl_cert_scanner script."""

    def test_missing_openssl_returns_error(self, mock_context):
        """Returns exit code 2 when openssl not available."""
        from scripts.baremetal import ssl_cert_scanner

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = ssl_cert_scanner.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("openssl" in e.lower() for e in output.errors)

    def test_no_certificates_found(self, mock_context):
        """Returns 0 with empty list when no certs found."""
        from scripts.baremetal import ssl_cert_scanner

        ctx = mock_context(
            tools_available=["openssl"],
            file_contents={},  # No files
        )
        output = Output()

        exit_code = ssl_cert_scanner.run(["-p", "/nonexistent"], output, ctx)

        assert exit_code == 0
        assert output.data["certificates"] == []
        assert output.data["summary"]["total"] == 0

    def test_all_certs_valid(self, mock_context, cert_valid):
        """Returns 0 when all certificates are valid."""
        from scripts.baremetal import ssl_cert_scanner

        # Use direct file paths to bypass glob matching issues
        ctx = mock_context(
            tools_available=["openssl"],
            file_contents={
                "/etc/ssl/certs/example.crt": "cert content",
                "/etc/ssl/certs/other.crt": "cert content",
            },
            command_outputs={
                ("openssl", "x509", "-in", "/etc/ssl/certs/example.crt", "-noout", "-subject", "-issuer", "-dates", "-serial"): cert_valid,
                ("openssl", "x509", "-in", "/etc/ssl/certs/other.crt", "-noout", "-subject", "-issuer", "-dates", "-serial"): cert_valid,
            },
        )
        output = Output()

        # Pass specific cert files directly using -p for each
        exit_code = ssl_cert_scanner.run(["-p", "/etc/ssl/certs/example.crt", "-p", "/etc/ssl/certs/other.crt"], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["valid"] == 2
        assert output.data["summary"]["expired"] == 0

    def test_expired_cert_returns_issues(self, mock_context, cert_expired):
        """Returns 1 when expired certificate found."""
        from scripts.baremetal import ssl_cert_scanner

        ctx = mock_context(
            tools_available=["openssl"],
            file_contents={
                "/etc/ssl/certs/old.crt": "cert content",
            },
            command_outputs={
                ("openssl", "x509", "-in", "/etc/ssl/certs/old.crt", "-noout", "-subject", "-issuer", "-dates", "-serial"): cert_expired,
            },
        )
        output = Output()

        exit_code = ssl_cert_scanner.run(["-p", "/etc/ssl/certs/old.crt"], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["expired"] == 1
        # Expired cert has negative days remaining
        assert output.data["certificates"][0]["days_remaining"] < 0
        assert output.data["certificates"][0]["status"] == "expired"

    def test_expiring_soon_cert_returns_issues(self, mock_context, cert_expiring):
        """Returns 1 when certificate expiring soon."""
        from scripts.baremetal import ssl_cert_scanner

        ctx = mock_context(
            tools_available=["openssl"],
            file_contents={
                "/etc/ssl/certs/staging.crt": "cert content",
            },
            command_outputs={
                ("openssl", "x509", "-in", "/etc/ssl/certs/staging.crt", "-noout", "-subject", "-issuer", "-dates", "-serial"): cert_expiring,
            },
        )
        output = Output()

        exit_code = ssl_cert_scanner.run(["-p", "/etc/ssl/certs/staging.crt", "--days", "30"], output, ctx)

        assert exit_code == 1
        # Should be warning since it expires within 30 days but not yet
        assert output.data["certificates"][0]["status"] in ("warning", "critical")

    def test_verbose_includes_details(self, mock_context, cert_valid):
        """Verbose mode includes issuer and subject details."""
        from scripts.baremetal import ssl_cert_scanner

        ctx = mock_context(
            tools_available=["openssl"],
            file_contents={
                "/etc/ssl/certs/example.crt": "cert content",
            },
            command_outputs={
                ("openssl", "x509", "-in", "/etc/ssl/certs/example.crt", "-noout", "-subject", "-issuer", "-dates", "-serial"): cert_valid,
            },
        )
        output = Output()

        exit_code = ssl_cert_scanner.run(["-p", "/etc/ssl/certs/example.crt", "--verbose"], output, ctx)

        assert exit_code == 0
        cert = output.data["certificates"][0]
        assert "subject" in cert
        assert "issuer" in cert
        assert "serial" in cert

    def test_warn_only_filters_valid(self, mock_context, cert_valid, cert_expired):
        """Warn-only mode filters out valid certificates."""
        from scripts.baremetal import ssl_cert_scanner

        ctx = mock_context(
            tools_available=["openssl"],
            file_contents={
                "/etc/ssl/certs/valid.crt": "cert content",
                "/etc/ssl/certs/expired.crt": "cert content",
            },
            command_outputs={
                ("openssl", "x509", "-in", "/etc/ssl/certs/valid.crt", "-noout", "-subject", "-issuer", "-dates", "-serial"): cert_valid,
                ("openssl", "x509", "-in", "/etc/ssl/certs/expired.crt", "-noout", "-subject", "-issuer", "-dates", "-serial"): cert_expired,
            },
        )
        output = Output()

        exit_code = ssl_cert_scanner.run(["-p", "/etc/ssl/certs/valid.crt", "-p", "/etc/ssl/certs/expired.crt", "--warn-only"], output, ctx)

        assert exit_code == 1
        # Only expired cert in results, but summary shows both
        assert len(output.data["certificates"]) == 1
        assert output.data["certificates"][0]["status"] == "expired"
        assert output.data["summary"]["total"] == 2
