import paramiko
import time

class SSH(paramiko.ServerInterface):
    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        with open("auth_attempts.log", "a") as f:
            f.write(f"{time.ctime()} - {username}:{password}\n")
        return paramiko.AUTH_SUCCESSFUL 

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

def handle_shell(channel):
    channel.send("\r\nUbuntu 22.04.1 LTS\r\n\r\n")
    
    buffer = ""
    while True:
        channel.send("root@server:~# ")
        line = ""
        while True:
            char = channel.recv(1)
            if not char:
                return
            
            if char == b'\r':
                channel.send("\r\n")
                break
            elif char == b'\x7f':
                if len(line) > 0:
                    line = line[:-1]
                    channel.send("\b \b")
            else:
                line += char.decode('utf-8', errors='ignore')
                channel.send(char)

        with open("commands.log", "a") as f:
            f.write(f"{time.ctime()} - {line}\n")

        cmd = line.strip()
        if cmd == "exit":
            channel.close()
            break
        elif cmd == "ls":
            channel.send("total 8\r\ndrwxr-xr-x 2 root root 4096 Oct 12 10:00 .\r\ndrwxr-xr-x 2 root root 4096 Oct 12 10:00 ..\r\n-rw-r--r-- 1 root root  156 Oct 12 10:05 config.php\r\n")
        elif cmd == "whoami":
            channel.send("root\r\n")
        elif cmd == "uname -a":
            channel.send("Linux server 5.15.0-48-generic #54-Ubuntu SMP Fri Aug 26 13:26:29 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux\r\n")
        elif cmd == "":
            pass
        else:
            channel.send(f"bash: {cmd}: command not found\r\n")