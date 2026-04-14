"""Tests for secret redaction."""

import os

from boxctl.core.redact import redact_value


class TestRedactAWS:
    def test_aws_access_key_id(self):
        assert redact_value("key=AKIAIOSFODNN7EXAMPLE rest") == "key=[REDACTED:aws-key] rest"

    def test_aws_temp_access_key(self):
        assert redact_value("ASIAIOSFODNN7EXAMPLE") == "[REDACTED:aws-key]"


class TestRedactPEM:
    def test_rsa_private_key(self):
        pem = "prefix -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK\nabc\n-----END RSA PRIVATE KEY----- suffix"
        assert redact_value(pem) == "prefix [REDACTED:pem-key] suffix"

    def test_ec_private_key(self):
        pem = "-----BEGIN EC PRIVATE KEY-----\nabc\n-----END EC PRIVATE KEY-----"
        assert redact_value(pem) == "[REDACTED:pem-key]"

    def test_openssh_private_key(self):
        pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
        assert redact_value(pem) == "[REDACTED:pem-key]"

    def test_plain_private_key(self):
        pem = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
        assert redact_value(pem) == "[REDACTED:pem-key]"


class TestRedactJWT:
    def test_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        assert redact_value(f"Authorization: Bearer {jwt}") == "Authorization: Bearer [REDACTED:jwt]"


class TestRedactAPIKey:
    def test_sk_key(self):
        assert redact_value("sk-proj-abcdefghijklmnopqrstuv") == "[REDACTED:api-key]"

    def test_sk_embedded(self):
        assert redact_value("token=sk-abcdefghijklmnopqrstuv end") == "token=[REDACTED:api-key] end"


class TestRedactDBCreds:
    def test_postgres(self):
        assert redact_value("postgres://alice:hunter2@db.local/app") == "postgres://[REDACTED:db-cred]@db.local/app"

    def test_postgresql(self):
        assert redact_value("postgresql://u:p@h/d") == "postgresql://[REDACTED:db-cred]@h/d"

    def test_mysql(self):
        assert redact_value("mysql://u:p@h:3306/d") == "mysql://[REDACTED:db-cred]@h:3306/d"

    def test_mongodb(self):
        assert redact_value("mongodb://u:p@h/d") == "mongodb://[REDACTED:db-cred]@h/d"

    def test_redis(self):
        assert redact_value("redis://u:p@h:6379") == "redis://[REDACTED:db-cred]@h:6379"


class TestRedactMultiple:
    def test_multiple_in_one_string(self):
        s = "key=AKIAIOSFODNN7EXAMPLE token=sk-abcdefghijklmnopqrstuv"
        result = redact_value(s)
        assert "[REDACTED:aws-key]" in result
        assert "[REDACTED:api-key]" in result
        assert "AKIA" not in result
        assert "sk-" not in result


class TestRedactRecursive:
    def test_dict(self):
        r = redact_value({"k": "AKIAIOSFODNN7EXAMPLE", "n": 1})
        assert r == {"k": "[REDACTED:aws-key]", "n": 1}

    def test_nested(self):
        r = redact_value({"outer": {"inner": ["AKIAIOSFODNN7EXAMPLE", 42]}})
        assert r == {"outer": {"inner": ["[REDACTED:aws-key]", 42]}}

    def test_non_string_passthrough(self):
        assert redact_value(42) == 42
        assert redact_value(None) is None
        assert redact_value(True) is True
        assert redact_value(3.14) == 3.14

    def test_tuple(self):
        assert redact_value(("AKIAIOSFODNN7EXAMPLE", 1)) == ("[REDACTED:aws-key]", 1)


class TestRedactInOutput:
    def test_render_json_redacts(self, capsys):
        from boxctl.core.output import Output
        o = Output()
        o.emit({"creds": "AKIAIOSFODNN7EXAMPLE"})
        o.render(format="json")
        captured = capsys.readouterr().out
        assert "AKIA" not in captured
        assert "[REDACTED:aws-key]" in captured

    def test_render_plain_redacts(self, capsys):
        from boxctl.core.output import Output
        o = Output()
        o.emit({"creds": "AKIAIOSFODNN7EXAMPLE"})
        o.render(format="plain")
        captured = capsys.readouterr().out
        assert "AKIA" not in captured
        assert "[REDACTED:aws-key]" in captured

    def test_no_redact_flag(self, capsys):
        from boxctl.core.output import Output
        o = Output()
        o.emit({"creds": "AKIAIOSFODNN7EXAMPLE"})
        o.render(format="json", redact=False)
        captured = capsys.readouterr().out
        assert "AKIAIOSFODNN7EXAMPLE" in captured

    def test_render_does_not_mutate_data(self):
        from boxctl.core.output import Output
        o = Output()
        o.emit({"creds": "AKIAIOSFODNN7EXAMPLE"})
        o.render(format="json")
        assert o.data["creds"] == "AKIAIOSFODNN7EXAMPLE"

    def test_env_var_disables_redaction(self, capsys, monkeypatch):
        from boxctl.core.output import Output
        monkeypatch.setenv("BOXCTL_NO_REDACT", "1")
        o = Output()
        o.emit({"creds": "AKIAIOSFODNN7EXAMPLE"})
        o.render(format="json")
        assert "AKIAIOSFODNN7EXAMPLE" in capsys.readouterr().out

    def test_cli_no_redact_flag_sets_env(self, monkeypatch):
        from boxctl.cli import main
        monkeypatch.delenv("BOXCTL_NO_REDACT", raising=False)
        # No command -> prints help, returns 0; we only want the pre-command env wiring.
        main(["--no-redact"])
        assert os.environ.get("BOXCTL_NO_REDACT") == "1"
