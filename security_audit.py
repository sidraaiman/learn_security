import re
import ssl
import socket
import requests
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime

# -----------------------------
# Step 1: Parse Apache/Nginx log file
# -----------------------------
log_pattern = re.compile(
    r'(?P<ip>\S+) - - \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d{3}) (?P<size>\d+)'
)

def parse_logs(log_file):
    logs = []
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            m = log_pattern.match(line)
            if m:
                logs.append(m.groupdict())
    return pd.DataFrame(logs)

# -----------------------------
# Step 2: Heuristic scoring
# -----------------------------
def calculate_score(df):
    score = 0
    reasons = []

    request_count = len(df)
    failed_responses = len(df[df["status"].astype(int) >= 400])
    urls = " ".join(df["url"].tolist())

    # Rule 1: Too many requests
    if request_count > 50:
        score += 30
        reasons.append("High request frequency")

    # Rule 2: Sensitive endpoints
    if "/admin" in urls or "/login" in urls:
        score += 20
        reasons.append("Sensitive endpoints accessed")

    # Rule 3: Too many failed logins
    if failed_responses > 10:
        score += 25
        reasons.append("Many failed login attempts")

    if score == 0:
        score = 5
        reasons.append("Normal behavior")

    return {"score": score, "reasons": reasons}

# -----------------------------
# Step 3: ML anomaly detection
# -----------------------------
def ml_detection(df):
    if df.empty:
        return "No logs to analyze"

    # Convert categorical features to numeric
    df_numeric = pd.DataFrame()
    df_numeric["status"] = df["status"].astype(int)
    df_numeric["method"] = pd.factorize(df["method"])[0]
    df_numeric["url_len"] = df["url"].str.len()
    df_numeric["hour"] = df["time"].apply(lambda x: int(x.split(":")[1]) if ":" in x else 0)

    model = IsolationForest(contamination=0.1, random_state=42)
    preds = model.fit_predict(df_numeric)

    anomalies = df[preds == -1]
    return anomalies

# -----------------------------
# Step 4: TLS check
# -----------------------------
def check_tls(domain):
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, 443)) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
            return {
                "issuer": dict(x[0] for x in cert['issuer']),
                "subject": dict(x[0] for x in cert['subject']),
                "valid_from": cert['notBefore'],
                "valid_to": cert['notAfter'],
                "tls_version": ssock.version()
            }

# -----------------------------
# Step 5: Security headers check
# -----------------------------
def check_headers(url):
    resp = requests.get(url, timeout=5)
    headers = resp.headers
    required = ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"]

    missing = [h for h in required if h not in headers]
    return {"present": dict(headers), "missing": missing}

# -----------------------------
# Main runner
# -----------------------------
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python security_audit.py <domain> <log_file>")
        sys.exit(1)

    domain = sys.argv[1]
    log_file = sys.argv[2]

    print(f"\n🔍 Analyzing logs from {log_file}...")
    df = parse_logs(log_file)
    print(df.head())

    print("\n📊 Heuristic Analysis:")
    print(calculate_score(df))

    print("\n🤖 ML Anomaly Detection:")
    anomalies = ml_detection(df)
    print(anomalies if not anomalies.empty else "No anomalies found")

    print("\n🔐 TLS Info:")
    print(check_tls(domain))

    print("\n📑 Security Headers:")
    print(check_headers("https://" + domain))
