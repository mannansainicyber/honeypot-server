import json
import argparse
from collections import Counter
from pathlib import Path


def load_entries(path="logs/credentials.json"):
    entries = []
    p = Path(path)
    if not p.exists():
        print("No credentials log found yet.")
        return entries
    for line in p.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return entries


def main():
    parser = argparse.ArgumentParser(description="SSH Honeypot Log Analyzer")
    parser.add_argument("--top", type=int, default=10, help="Show top N entries")
    parser.add_argument("--ip", type=str, help="Filter by IP address")
    args = parser.parse_args()

    entries = load_entries()
    if not entries:
        return

    if args.ip:
        entries = [e for e in entries if e.get("ip") == args.ip]
        print(f"\nEntries for IP {args.ip}: {len(entries)}\n")

    total = len(entries)
    ips = Counter(e["ip"] for e in entries)
    usernames = Counter(e["username"] for e in entries)
    passwords = Counter(e["password"] for e in entries)

    print(f"{'='*50}")
    print(f"  SSH Honeypot — Credential Summary")
    print(f"{'='*50}")
    print(f"  Total attempts : {total}")
    print(f"  Unique IPs     : {len(ips)}")
    print(f"  Unique users   : {len(usernames)}")
    print(f"  Unique passwords: {len(passwords)}")

    print(f"\n  Top {args.top} Attacker IPs:")
    for ip, count in ips.most_common(args.top):
        print(f"    {ip:<20} {count} attempts")

    print(f"\n  Top {args.top} Usernames:")
    for u, count in usernames.most_common(args.top):
        print(f"    {u:<20} {count}x")

    print(f"\n  Top {args.top} Passwords:")
    for p, count in passwords.most_common(args.top):
        print(f"    {p:<20} {count}x")

    print(f"{'='*50}\n")


if __name__ == "__main__":
    main()