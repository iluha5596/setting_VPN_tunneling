#!/usr/bin/env python3
"""Local credential setup and pinned SSH transport. Not a one-click VPN installer."""
import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import sys
import time


class ConfigError(Exception):
    pass


def read_config(path):
    path = Path(path).expanduser().resolve()
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        raise ConfigError("Cannot read configuration; check path and JSON syntax (values hidden).") from None
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ConfigError("Expected schema_version 1.")
    servers = data.get("servers")
    if not isinstance(servers, dict) or set(servers) != {"ru", "exit"}:
        raise ConfigError("Expected exactly servers.ru and servers.exit.")
    for role, server in servers.items():
        if not isinstance(server, dict):
            raise ConfigError(f"{role}: expected object.")
        host = server.get("host", "")
        if not isinstance(host, str) or not host or len(host) > 253:
            raise ConfigError(f"{role}: host is required.")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host):
                raise ConfigError(f"{role}: host must be an IP or DNS name, not a URL.")
        port = server.get("port", 22)
        if type(port) is not int or not 1 <= port <= 65535:
            raise ConfigError(f"{role}: invalid port.")
        if not isinstance(server.get("username"), str) or not server["username"]:
            raise ConfigError(f"{role}: username required.")
        auth = server.get("auth", {})
        if not isinstance(auth, dict):
            raise ConfigError(f"{role}: invalid auth.")
        if auth.get("type") == "password":
            if not isinstance(auth.get("password"), str) or not auth["password"]:
                raise ConfigError(f"{role}: fill password locally.")
            if auth.get("private_key_path"):
                raise ConfigError(f"{role}: choose only one authentication method.")
        elif auth.get("type") == "key":
            raw = auth.get("private_key_path")
            if not isinstance(raw, str) or not raw:
                raise ConfigError(f"{role}: private_key_path required.")
            key = Path(raw).expanduser()
            if not key.is_absolute():
                key = path.parent / key
            if not key.is_file():
                raise ConfigError(f"{role}: private key file not found.")
            auth["private_key_path"] = str(key.resolve())
            if auth.get("password"):
                raise ConfigError(f"{role}: choose only one authentication method.")
            if not isinstance(auth.get("passphrase", ""), str):
                raise ConfigError(f"{role}: passphrase must be a string.")
        else:
            raise ConfigError(f"{role}: auth.type must be password or key.")
        pin = server.get("host_key_sha256", "")
        if not isinstance(pin, str) or (pin and not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", pin)):
            raise ConfigError(f"{role}: expected OpenSSH SHA256 fingerprint or empty string.")
    if (servers["ru"]["host"], servers["ru"].get("port", 22)) == (servers["exit"]["host"], servers["exit"].get("port", 22)):
        raise ConfigError("RU and EXIT must be distinct SSH targets.")
    return data


def init(directory):
    dest = Path(directory).expanduser().resolve()
    dest.mkdir(mode=0o700, parents=True, exist_ok=True)
    assets = Path(__file__).resolve().parents[1] / "assets"
    for template, filename in (("servers.example.json", "servers.private.json"), ("plan.example.json", "plan.json")):
        target = dest / filename
        # Exclusive create: never overwrite credentials, including when rerun.
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            print(f"Preserved: {target}")
            continue
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write((assets / template).read_text(encoding="utf-8"))
        print(f"Created: {target}")
    for folder in ("backups", "clients", "generated"):
        (dest / folder).mkdir(mode=0o700, exist_ok=True)
    ignore = dest / ".gitignore"
    if not ignore.exists():
        ignore.write_text("*\n", encoding="utf-8")
    if os.name == "nt":
        print("Windows: check folder ACL; POSIX mode alone does not restrict Windows access.")


def fingerprint(key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def redact(text, data):
    secrets = []
    for server in data["servers"].values():
        auth = server["auth"]
        secrets.extend(auth.get(k, "") for k in ("password", "passphrase"))
    for secret in sorted(filter(None, secrets), key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    return text


def paramiko_module():
    try:
        import paramiko
        return paramiko
    except ImportError:
        raise ConfigError("Install Paramiko in a local venv: python -m pip install 'paramiko>=3.5,<5'") from None


def scan(server):
    paramiko = paramiko_module()
    # No password or private key is used during this untrusted discovery.
    with socket.create_connection((server["host"], server.get("port", 22)), timeout=15) as sock:
        transport = paramiko.Transport(sock)
        try:
            transport.start_client(timeout=15)
            key = transport.get_remote_server_key()
            print(json.dumps({"status": "UNVERIFIED", "host": server["host"], "algorithm": key.get_name(), "fingerprint": fingerprint(key)}))
        finally:
            transport.close()


def connect(server):
    paramiko = paramiko_module()
    client = paramiko.SSHClient()
    pin = server.get("host_key_sha256", "")
    if pin:
        class PinnedPolicy(paramiko.MissingHostKeyPolicy):
            def missing_host_key(self, client, hostname, key):
                if not hmac.compare_digest(fingerprint(key), pin):
                    raise paramiko.SSHException("Host key fingerprint mismatch; independently verify the server.")
        client.set_missing_host_key_policy(PinnedPolicy())
    else:
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    auth = server["auth"]
    args = dict(hostname=server["host"], port=server.get("port", 22), username=server["username"],
                timeout=20, banner_timeout=20, auth_timeout=20, allow_agent=False, look_for_keys=False)
    if auth["type"] == "password":
        args["password"] = auth["password"]
    else:
        args["key_filename"] = auth["private_key_path"]
        args["passphrase"] = auth.get("passphrase") or None
    try:
        client.connect(**args)
        client.get_transport().set_keepalive(15)
        return client
    except Exception:
        client.close()
        raise


def run(client, script, timeout):
    payload = Path(script).read_text(encoding="utf-8-sig").replace("\r\n", "\n")
    if len(payload.encode()) > 1_000_000:
        raise ConfigError("Script too large; upload an inspected file separately.")
    stdin, stdout, stderr = client.exec_command("bash -s", timeout=timeout)
    stdin.write(payload + "\n")
    stdin.flush()
    stdin.channel.shutdown_write()
    channel = stdout.channel
    chunks = []
    size = 0
    deadline = time.monotonic() + timeout
    try:
        while True:
            for ready, recv in ((channel.recv_ready, channel.recv), (channel.recv_stderr_ready, channel.recv_stderr)):
                if ready():
                    chunk = recv(65536)
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > 2_000_000:
                        raise ConfigError("Output limit exceeded. Inspect remote state before retrying.")
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            if time.monotonic() >= deadline:
                raise ConfigError("SSH timeout. Remote work may still be running; inspect state before retrying.")
            time.sleep(0.02)
        return channel.recv_exit_status(), b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        channel.close()


def transfer(client, action, local, remote):
    if not remote.startswith("/") or "\x00" in remote:
        raise ConfigError("Remote path must be absolute.")
    local = Path(local).expanduser().resolve()
    with client.open_sftp() as sftp:
        if action == "get":
            local.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            # Do not truncate a prior backup.
            fd = os.open(local, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                sftp.getfo(remote, stream)
            digest = hashlib.sha256()
            with local.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            print(f"Downloaded SHA256 {digest.hexdigest()}  {local}")
        else:
            # Parent must already exist. Exclusive create prevents accidental overwrite.
            with sftp.open(remote, "wx") as target:
                sftp.chmod(remote, 0o600)
                with local.open("rb") as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        target.write(chunk)
            print("Uploaded new private file.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("init").add_argument("--dir", required=True)
    for action in ("validate", "scan", "run", "get", "put"):
        cmd = sub.add_parser(action)
        cmd.add_argument("--config", required=True)
        if action != "validate":
            cmd.add_argument("--server", choices=("ru", "exit"), required=True)
        if action == "run":
            cmd.add_argument("--script", required=True)
            cmd.add_argument("--timeout", type=int, default=300)
        if action in ("get", "put"):
            cmd.add_argument("--local", required=True)
            cmd.add_argument("--remote", required=True)
    args = parser.parse_args(argv)
    data = None
    try:
        if args.action == "init":
            init(args.dir)
            return 0
        data = read_config(args.config)
        if args.action == "validate":
            print("Configuration valid. Credentials hidden. Connectivity and server trust not tested.")
            return 0
        server = data["servers"][args.server]
        if args.action == "scan":
            scan(server)
            return 0
        client = connect(server)
        try:
            if args.action == "run":
                code, output = run(client, args.script, args.timeout)
                print(redact(output, data), end="")
                return code
            transfer(client, args.action, args.local, args.remote)
            return 0
        finally:
            client.close()
    except Exception as exc:
        message = str(exc) if isinstance(exc, ConfigError) else f"Operation failed ({type(exc).__name__}); inspect connectivity, host trust and private local settings."
        print(redact(message, data) if data else message, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
