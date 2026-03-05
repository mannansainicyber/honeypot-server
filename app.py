import socket
import threading
import logging
import json
import os
import smtplib
import paramiko
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import load_config

# ── Logging setup ────────────────────────────────────────────────────────────

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/honeypot.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("ssh-honeypot")

# JSON credential log
cred_logger = logging.getLogger("credentials")
cred_handler = logging.FileHandler("logs/credentials.json")
cred_logger.addHandler(cred_handler)
cred_logger.setLevel(logging.INFO)


# ── Email alerts ─────────────────────────────────────────────────────────────

def send_alert(cfg, ip: str, username: str, password: str):
    """Send an email alert when a login attempt is captured."""
    if not cfg.get("email_enabled"):
        return
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[Honeypot] Login attempt from {ip}"
        msg["From"] = cfg["email_from"]
        msg["To"] = cfg["email_to"]

        body = (
            f"<h3>SSH Honeypot Alert</h3>"
            f"<b>Time:</b> {datetime.utcnow().isoformat()} UTC<br>"
            f"<b>IP:</b> {ip}<br>"
            f"<b>Username:</b> {username}<br>"
            f"<b>Password:</b> {password}"
        )
        msg.attach(MIMEText(body, "html"))

        with smtplib.SMTP_SSL(cfg["smtp_host"], cfg["smtp_port"]) as server:
            server.login(cfg["smtp_user"], cfg["smtp_pass"])
            server.sendmail(cfg["email_from"], cfg["email_to"], msg.as_string())

        logger.info(f"Alert email sent for {ip}")
    except Exception as e:
        logger.error(f"Failed to send alert email: {e}")


# ── Fake SSH server interface ─────────────────────────────────────────────────

class HoneypotInterface(paramiko.ServerInterface):
    def __init__(self, client_ip: str, cfg: dict):
        self.client_ip = client_ip
        self.cfg = cfg
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str):
        """Always reject but log every credential attempt."""
        timestamp = datetime.utcnow().isoformat()

        # Log to credentials JSON file
        entry = {
            "timestamp": timestamp,
            "ip": self.client_ip,
            "username": username,
            "password": password,
        }
        cred_logger.info(json.dumps(entry))

        # Log to main log
        logger.warning(
            f"LOGIN ATTEMPT | IP: {self.client_ip} | user: {username!r} | pass: {password!r}"
        )

        # Fire email alert in background
        threading.Thread(
            target=send_alert,
            args=(self.cfg, self.client_ip, username, password),
            daemon=True,
        ).start()

        # Always deny — but delay to slow brute-force
        import time; time.sleep(1)
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"


# ── Per-client handler ────────────────────────────────────────────────────────

def handle_client(client_sock: socket.socket, client_addr: tuple, host_key, cfg: dict):
    ip = client_addr[0]
    logger.info(f"New connection from {ip}:{client_addr[1]}")

    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = cfg.get("banner", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
        transport.add_server_key(host_key)

        server_iface = HoneypotInterface(ip, cfg)
        transport.start_server(server=server_iface)

        # Keep connection open briefly to harvest more attempts
        channel = transport.accept(timeout=30)
        if channel:
            channel.send(b"Permission denied.\r\n")
            channel.close()

    except (paramiko.SSHException, EOFError, ConnectionResetError) as e:
        logger.debug(f"SSH error from {ip}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error from {ip}: {e}")
    finally:
        if transport:
            transport.close()
        client_sock.close()
        logger.info(f"Connection closed: {ip}")


# ── Main server loop ──────────────────────────────────────────────────────────

def run(cfg: dict):
    host = cfg.get("host", "0.0.0.0")
    port = cfg.get("port", 2222)

    # Generate or load RSA host key
    key_path = cfg.get("host_key_path", "config/server.key")
    if os.path.exists(key_path):
        host_key = paramiko.RSAKey(filename=key_path)
        logger.info(f"Loaded host key from {key_path}")
    else:
        host_key = paramiko.RSAKey.generate(2048)
        host_key.write_private_key_file(key_path)
        logger.info(f"Generated new RSA host key → {key_path}")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(100)

    logger.info(f"SSH Honeypot listening on {host}:{port}")

    try:
        while True:
            client_sock, client_addr = server_sock.accept()
            t = threading.Thread(
                target=handle_client,
                args=(client_sock, client_addr, host_key, cfg),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        logger.info("Shutting down honeypot.")
    finally:
        server_sock.close()


if __name__ == "__main__":
    cfg = load_config()
    run(cfg)