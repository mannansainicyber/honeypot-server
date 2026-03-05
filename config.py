import json
import os


DEFAULTS = {
    "host": "0.0.0.0",
    "port": 2222,
    "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
    "host_key_path": "config/server.key",

    # Email alerts (set email_enabled to true and fill in your details)
    "email_enabled": False,
    "email_from": "honeypot@example.com",
    "email_to": "you@example.com",
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 465,
    "smtp_user": "honeypot@example.com",
    "smtp_pass": "your_app_password",
}


def load_config(path: str = "config/settings.json") -> dict:
    cfg = DEFAULTS.copy()
    if os.path.exists(path):
        with open(path) as f:
            overrides = json.load(f)
        cfg.update(overrides)
        print(f"[config] Loaded settings from {path}")
    else:
        print(f"[config] No settings.json found — using defaults. "
              f"Copy config/settings.example.json to {path} to customise.")
    return cfg