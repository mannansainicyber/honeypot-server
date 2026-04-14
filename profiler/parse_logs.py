import re
import pandas as pd
from collections import defaultdict

def parse_logs(
    auth_log="auth_attempts.log",
    cmd_log="commands.log",
    session_log="sessions.log"
):
    sessions = {}
    with open(session_log) as f:
        for line in f:
            m = re.search(r"\[(.+?)\] SESSION_(\w+)(?:.*duration=([\d.]+)s)?", line)
            if not m: continue
            ip, event, duration = m.group(1), m.group(2), m.group(3)
            if ip not in sessions:
                sessions[ip] = {"duration": 0, "session_count": 0}
            if event == "START":
                sessions[ip]["session_count"] += 1
            if event == "END" and duration:
                sessions[ip]["duration"] += float(duration)

    auth = defaultdict(list)
    with open(auth_log) as f:
        for line in f:
            m = re.search(r"\[(.+?)\] (\S+):(\S+)", line)
            if not m: continue
            ip, user, pwd = m.group(1), m.group(2), m.group(3)
            auth[ip].append((user, pwd))

    cmds = defaultdict(list)
    with open(cmd_log) as f:
        for line in f:
            m = re.search(r"\[(.+?)\] \[(.+?)\] (.+)", line)  # fixed
            if not m: continue
            ip, cwd, command = m.group(1), m.group(2), m.group(3).strip()
            cmds[ip].append(command)

    all_ips = set(list(sessions.keys()) + list(auth.keys()) + list(cmds.keys()))
    rows = []
    for ip in all_ips:
        attempts = auth.get(ip, [])
        commands = cmds.get(ip, [])
        sess = sessions.get(ip, {"duration": 0, "session_count": 1})
        cmd_text = " ".join(commands).lower()
        rows.append({
            "ip":               ip,
            "session_duration": sess["duration"],
            "session_count":    sess["session_count"],
            "auth_attempts":    len(attempts),
            "unique_passwords": len(set(p for _, p in attempts)),
            "unique_usernames": len(set(u for u, _ in attempts)),
            "command_count":    len(commands),
            "unique_commands":  len(set(commands)),
            "tried_config":     int("config.php" in cmd_text),
            "tried_passwd":     int("passwd" in cmd_text),
            "tried_history":    int("bash_history" in cmd_text or "history" in cmd_text),
            "tried_whoami":     int("whoami" in cmd_text),
            "tried_restricted": int(any(c in cmd_text for c in ["wget","curl","python3","sudo"])),
            "navigated_dirs":   int("cd " in cmd_text),
        })
    return pd.DataFrame(rows)

if __name__ == "__main__":
    df = parse_logs()
    if df.empty:
        print("No data parsed")
    else:
        print(df.to_string())