"""SSH host keys: trust on first use, refuse a changed key.

Runs a throwaway paramiko server on localhost, so it needs no network.
"""
import logging
import socket
import threading

import pytest

paramiko = pytest.importorskip("paramiko")
from connectors.ssh_executor import SSHConfig, SSHExecutor  # noqa: E402


class _Deny(paramiko.ServerInterface):
    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        return paramiko.AUTH_FAILED


def _serve(key):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)

    def run():
        conn, _ = s.accept()
        t = paramiko.Transport(conn)
        t.add_server_key(key)
        try:
            t.start_server(server=_Deny())
            t.accept(5)
        except Exception:
            pass

    threading.Thread(target=run, daemon=True).start()
    return s.getsockname()[1]


def test_first_contact_recorded_and_changed_key_refused(tmp_path, monkeypatch, caplog):
    kh = tmp_path / "known_hosts"
    monkeypatch.setenv("SSH_KNOWN_HOSTS", str(kh))
    caplog.set_level(logging.ERROR)
    key1, key2 = paramiko.RSAKey.generate(2048), paramiko.RSAKey.generate(2048)

    port = _serve(key1)        # login fails, but the key must still be recorded
    cfg = SSHConfig(hostname="127.0.0.1", port=port, username="u", password="x", timeout=10)
    assert SSHExecutor(cfg).connect() is False
    assert paramiko.HostKeys(str(kh)).lookup(f"[127.0.0.1]:{port}")["ssh-rsa"] == key1
    assert "CHANGED" not in caplog.text

    port2 = _serve(key2)       # same address on file, different key
    kh.write_text(kh.read_text().replace(f"[127.0.0.1]:{port}", f"[127.0.0.1]:{port2}"))
    cfg.port = port2
    assert SSHExecutor(cfg).connect() is False
    assert "CHANGED" in caplog.text
