import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from parse_logs import parse_logs
from profiler import profile

PROFILE_DESCRIPTIONS = {
    "credential_stuffer": "Automated bot spraying password lists. Lots of attempts, no real exploration.",
    "automated_scanner":  "Port scanner or bot. Connected briefly, did almost nothing.",
    "data_thief":         "Actively hunting credentials. Went for config files or user lists.",
    "malware_dropper":    "Tried to download or execute something. High risk.",
    "manual_explorer":    "Human attacker poking around manually. Slow, curious.",
}

def report(df):
    print("=" * 45)
    print("       HONEYPOT ATTACKER REPORT")
    print("=" * 45)
    print(f"  Total attackers : {len(df)}")
    print()
    for _, row in df.iterrows():
        profile_name = row.get("profile", "unkown")
        desc = PROFILE_DESCRIPTIONS.get(profile_name, "unkown behaviour")

        flags = []
        if row["tried_config"]:     flags.append("went for config.php")
        if row["tried_passwd"]:     flags.append("read /etc/passwd")
        if row["tried_restricted"]: flags.append("tried wget/curl/sudo")
        if row["tried_history"]:    flags.append("read bash history")
        if row["tried_whoami"]:     flags.append("checked whoami")
        if row["navigated_dirs"]:   flags.append("navigated directories")
        flag_str = ", ".join(flags) if flags else "nothing suspicious"

        print(f"  IP       : {row['ip']}")
        print(f"  Profile  : {profile_name.upper()}")
        print(f"  Desc     : {desc}")
        print(f"  Session  : {row['session_duration']}s  ({int(row['session_count'])} connection(s))")
        print(f"  Auth     : {int(row['auth_attempts'])} attempt(s), {int(row['unique_passwords'])} unique password(s)")
        print(f"  Commands : {int(row['command_count'])} total, {int(row['unique_commands'])} unique")
        print(f"  Flags    : {flag_str}")
        print("-" * 45)


if __name__ == "__main__":
    df = parse_logs()
    df = profile(df)
    report(df)
