from datetime import datetime
class CommandDispatcher:
    def __init__(self):
        # Map commands to methods
        self.commands = {
            "ls": self.cmd_ls,
            "whoami": self.cmd_whoami,
            "id": self.cmd_id,
            "uname": self.cmd_uname,
            "pwd": self.cmd_pwd,
            "exit": self.cmd_exit,
            "": self.cmd_nop,
            "cat": self.cmd_cat,
            "echo": self.cmd_echo,
            "clear": self.cmd_clear,
            "hostname": self.cmd_hostname,
            "date": self.cmd_date,
        }

    def execute(self, cmd_line):
        parts = cmd_line.split()
        if not parts:
            return self.cmd_nop()
        
        base_cmd = parts[0]
        handler = self.commands.get(base_cmd)
        
        if handler:
            return handler(parts[1:])
        else:
            return f"sh: 1: {base_cmd}: not found\r\n", False

    # --- Command Implementations ---
    def cmd_date(self,args):
        now = datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y")
        return f"{now}\r\n", False
    def cmd_ls(self, args):
        return "total 4\r\n-rw-r--r-- 1 root root 1024 Mar  9 21:18 .bash_history\r\n", False
    def cmd_cat(self, args):
        if not args:
            return "", False
        # args[0] is the first argument after 'cat'
        filename = args[0].strip()
        if filename == ".bash_history":
            return f"cat: {filename}: Permission denied\r\n", False
        else:
            return f"cat: {filename}: No such file or directory\r\n", False
    def cmd_echo(self, args):
        output = " ".join(args) + "\r\n"
        return output, False

    def cmd_clear(self, args):
        return "\033[H\033[2J", False

    def cmd_hostname(self, args):
        return "ubuntu\r\n", False
    
    def cmd_whoami(self, args):
        return "root\r\n", False

    def cmd_id(self, args):
        return "uid=0(root) gid=0(root) groups=0(root)\r\n", False

    def cmd_uname(self, args):
        return "Linux ubuntu 5.15.0-generic #54-Ubuntu SMP x86_64 GNU/Linux\r\n", False

    def cmd_pwd(self, args):
        return "/root\r\n", False

    def cmd_exit(self, args):
        return "logout\r\n", True  # True signals the shell to close

    def cmd_nop(self, args=None):
        return "", False
    
