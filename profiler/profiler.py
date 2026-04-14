# profiler/profiler.py
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from parse_logs import parse_logs

FEATURE_COLS = [
    "session_duration", "auth_attempts", "unique_passwords",
    "command_count", "unique_commands", "tried_config",
    "tried_passwd", "tried_restricted", "navigated_dirs"
]

def label_cluster(group):
    if group["auth_attempts"].mean() > 10 and group["command_count"].mean() < 3:
        return "credential_stuffer"
    elif group["session_duration"].mean() < 5 and group["command_count"].mean() < 2:
        return "automated_scanner"
    elif group["tried_config"].mean() > 0.5 or group["tried_passwd"].mean() > 0.5:
        return "data_thief"
    elif group["tried_restricted"].mean() > 0.5:
        return "malware_dropper"
    else:
        return "manual_explorer"

def profile(df):
    if len(df) < 4:
        df["profile"] = df.apply(lambda row: label_cluster(df[df["ip"] == row["ip"]]), axis=1)
        print(f"Only {len(df)} attacker(s) — need at least 4 to cluster.")
        print("Showing raw data instead:\n")
        print(df[["ip"] + FEATURE_COLS].to_string())
        return df

    X = StandardScaler().fit_transform(df[FEATURE_COLS])
    df["cluster"] = KMeans(n_clusters=4, random_state=42, n_init=10).fit_predict(X)

    cluster_labels = {}
    for cid in df["cluster"].unique():
        group = df[df["cluster"] == cid]
        cluster_labels[cid] = label_cluster(group)
    df["profile"] = df["cluster"].map(cluster_labels)

    return df

if __name__ == "__main__":
    df = parse_logs()
    df = profile(df)
    print("\n=== Attacker Profiles ===\n")
    print(df[["ip", "session_duration", "auth_attempts",
              "command_count", "tried_config", "profile"]].to_string())