import paramiko
import time
import socket
import threading

banner = (
    "\r\nWelcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.17.0-19-generic x86_64)\r\n"
    "\r\n"
    " * Documentation:  https://help.ubuntu.com\r\n"
    " * Management:     https://landscape.canonical.com\r\n"
    " * Support:        https://ubuntu.com/pro\r\n"
    "\r\n"
    "Expanded Security Maintenance for Applications is not enabled.\r\n"
    "\r\n"
    "22 updates can be applied immediately.\r\n"
    "To see these additional updates run: apt list --upgradable\r\n"
    "\r\n"
    "35 additional security updates can be applied with ESM Apps.\r\n"
    "Learn more about enabling ESM Apps service at https://ubuntu.com/esm\r\n"
    "\r\n"
)

class SSH(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.event = threading.Event()
        self.client_ip = client_ip

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        with open("auth_attempts.log", "a") as f:
            f.write(f"{time.ctime()} - [{self.client_ip}] {username}:{password}\n")
        return paramiko.AUTH_SUCCESSFUL 

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pxwidth, pxheight, modes):
        return True

def handle_shell(channel, client_ip):
    channel.send(banner)
    cwd = "/root"
    
    session_start = time.time()
    with open("sessions.log", "a") as f:
        f.write(f"{time.ctime()} - [{client_ip}] SESSION_START\n")
    try:
        filesystem = {
            "/root": {
                "config.php": "<?php\n$db_user = 'admin';\n$db_pass = 'P@ssw0rd123';\n?>",
                "notes.txt": "Review server logs for suspicious IP: 194.26.29.11",
                ".bash_history": "ls -la\ncat /etc/passwd\nexit"
            },
            "/etc": {
                "passwd": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
                "hostname": "ubuntu-srv-01",
                "issue": "Ubuntu 24.04.4 LTS"
            }
        }

        while True:
            path_display = "~" if cwd == "/root" else cwd
            channel.send(f"root@server:{path_display}# ")
            line = ""
            while True:
                char = channel.recv(1)
                if not char: return
                if char == b'\r':
                    channel.send("\r\n")
                    break
                elif char == b'\x7f': # Backspace
                    if len(line) > 0:
                        line = line[:-1]
                        channel.send("\b \b")
                elif char == b'\x03': # Ctrl+C
                    channel.send("^C\r\n")
                    line = ""
                    break
                else:
                    line += char.decode('utf-8', errors='ignore')
                    channel.send(char)

            if not line.strip(): continue

            with open("commands.log", "a") as f:
                f.write(f"{time.ctime()} - [{client_ip}] [{cwd}] {line}\n")

            parts = line.strip().split()
            cmd = parts[0]
            args = parts[1:]

            if cmd == "exit":
                channel.send("logout\r\n")
                channel.close()
                break
            elif cmd == "ls":
                if cwd in filesystem:
                    channel.send("  ".join(filesystem[cwd].keys()) + "\r\n")
                else:
                    channel.send("\r\n")
            elif cmd == "cd":
                target = args[0] if args else "/root"
                if target == "..":
                    cwd = "/" if cwd == "/root" else "/root"
                elif target in filesystem or target == "/":
                    cwd = target
                else:
                    channel.send(f"-bash: cd: {target}: No such file or directory\r\n")
            elif cmd == "pwd":
                channel.send(f"{cwd}\r\n")
            elif cmd == "cat":
                if args:
                    filename = args[0]
                    if cwd in filesystem and filename in filesystem[cwd]:
                        content = filesystem[cwd][filename].replace("\n", "\r\n")
                        channel.send(f"{content}\r\n")
                    else:
                        channel.send(f"cat: {filename}: No such file or directory\r\n")
                else:
                    channel.send("usage: cat [file]\r\n")
            elif cmd == "whoami":
                channel.send("root\r\n")
            elif cmd == "uname":
                if "-a" in args:
                    channel.send("Linux server 6.17.0-19-generic #19-Ubuntu SMP PREEMPT_DYNAMIC x86_64 GNU/Linux\r\n")
                else:
                    channel.send("Linux\r\n")
            elif cmd in ["sudo", "apt", "wget", "curl", "python3"]:
                channel.send(f"-bash: {cmd}: command restricted\r\n")
            else:
                channel.send(f"bash: {cmd}: command not found\r\n")
    finally:
        duration = round(time.time() - session_start, 2)
        with open("sessions.log", "a") as f:
            f.write(f"{time.ctime()} - [{client_ip}] SESSION_END duration={duration}s\n")