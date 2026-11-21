"""Local tests only. No real VPS or credentials are used."""
import contextlib
import copy
import io
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
import paramiko
import control


class Server(paramiko.ServerInterface):
    def __init__(self):
        self.auth_calls = 0
        self.exec_received = threading.Event()

    def check_auth_password(self, username, password):
        self.auth_calls += 1
        return paramiko.AUTH_SUCCESSFUL if username == "root" and password == "test-secret-ONLY" else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        self.exec_received.set()
        return command == b"bash -s"


@contextlib.contextmanager
def local_server():
    key = paramiko.RSAKey.generate(2048)
    server = Server()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)
    port = listener.getsockname()[1]
    errors = []

    def worker():
        transport = None
        try:
            sock, _ = listener.accept()
            transport = paramiko.Transport(sock)
            transport.add_server_key(key)
            transport.start_server(server=server)
            channel = transport.accept(5)
            if channel is not None:
                channel.settimeout(5)
                server.exec_received.wait(5)
                data = b""
                while True:
                    chunk = channel.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                # Echo a known test password to verify that helper masks it.
                channel.sendall(b"OK test-secret-ONLY\n")
                channel.send_exit_status(7 if b"fail" in data else 0)
                channel.shutdown_write()
                # Let the client read all output before tearing down transport.
                for _ in range(100):
                    if channel.closed:
                        break
                    threading.Event().wait(0.01)
        except (EOFError, ConnectionResetError, paramiko.SSHException):
            pass  # Expected for rejected fingerprints.
        except Exception as exc:
            errors.append(exc)
        finally:
            if transport:
                transport.close()
    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    try:
        yield {"host": "127.0.0.1", "port": port, "username": "root", "auth": {"type": "password", "password": "test-secret-ONLY"}, "host_key_sha256": control.fingerprint(key)}, server
    finally:
        listener.close()
        thread.join(7)
        if thread.is_alive():
            raise AssertionError("Test SSH server failed to stop")
        if errors:
            raise errors[0]


class Tests(unittest.TestCase):
    def test_init_never_overwrites_and_template_requires_credentials(self):
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()):
            control.init(folder)
            config = Path(folder) / "servers.private.json"
            with self.assertRaises(control.ConfigError):
                control.read_config(config)
            config.write_text("preserve", encoding="utf-8")
            control.init(folder)
            self.assertEqual(config.read_text(), "preserve")

    def test_fingerprint_rejected_before_authentication(self):
        with local_server() as (server, observer):
            server["host_key_sha256"] = "SHA256:" + "A" * 43
            with self.assertRaises(paramiko.SSHException):
                control.connect(server)
            self.assertEqual(observer.auth_calls, 0)

    def test_actual_ssh_execution_exit_code_and_redaction(self):
        with local_server() as (server, observer), tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "config.json"
            other = copy.deepcopy(server)
            other["host"] = "localhost"
            config.write_text(json.dumps({"schema_version": 1, "servers": {"ru": server, "exit": other}}), encoding="utf-8")
            script = Path(folder) / "test.sh"
            script.write_text("echo fail\n", encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = control.main(["run", "--config", str(config), "--server", "ru", "--script", str(script), "--timeout", "10"])
            self.assertEqual(result, 7)
            self.assertIn("[REDACTED]", output.getvalue())
            self.assertNotIn("test-secret-ONLY", output.getvalue())
            self.assertEqual(observer.auth_calls, 1)

    def test_scan_is_unverified_and_does_not_authenticate(self):
        with local_server() as (server, observer), contextlib.redirect_stdout(io.StringIO()) as out:
            control.scan(server)
            self.assertIn("UNVERIFIED", out.getvalue())
            self.assertEqual(observer.auth_calls, 0)


if __name__ == "__main__":
    unittest.main()
