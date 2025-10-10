"""
passive_vuln_assessor_ml.py

Extension of passive_vuln_assessor.py — adds ML tracking of vulnerable websites.

Usage examples:

# 1) Assess a single site passively (LLM optional)
python passive_vuln_assessor_ml.py assess https://example.com --openai-key YOUR_KEY

# 2) Batch-assess a list of domains (one per line) and save features to CSV
python passive_vuln_assessor_ml.py batch_assess domains.txt features.csv

# 3) Train Isolation Forest from features CSV
python passive_vuln_assessor_ml.py train_iso features.csv iso_model.joblib

# 4) Predict & append new vulnerable sites using saved model
python passive_vuln_assessor_ml.py predict_and_track https://example.com iso_model.joblib vulnerable_websites.csv

# 5) Train supervised XGBoost (requires label column in CSV)
python passive_vuln_assessor_ml.py train_xgb labeled_features.csv xgb_model.joblib
"""

import argparse, json, datetime, ipaddress, os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Optional XGBoost / openai
try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except Exception:
    XGBOOST_AVAILABLE = False

try:
    import openai
    OPENAI_AVAILABLE = True
except Exception:
    OPENAI_AVAILABLE = False

# --- Import or copy the passive collector + heuristics functions from your earlier file.
# If you have the earlier file in the same folder, import it:
# from passive_vuln_assessor import normalize_url, resolve_hostname, get_cert_info, fetch_headers, fetch_path, heuristics, call_llm_assess
#
# If not, copy the necessary functions here. For brevity, this file assumes those functions exist
# and are importable. Otherwise copy them into this file.

# --- For demonstration, a minimal local shim of heuristics function signature used earlier:
# (Replace this by importing heuristics() from your passive_vuln_assessor.py to keep consistent.)
def heuristics(summary):
    # This should return {'score': int, 'level': str, 'reasons': [...], 'ml_features': {..}}
    # In your real program, import heuristics() from passive_vuln_assessor.py
    # Here is a placeholder that expects summary["http_headers"] and ["tls"], etc.
    headers = summary.get("http_headers", {}).get("headers", {}) or {}
    xp = 1 if headers.get("x-powered-by") else 0
    missing_count = sum(1 for h in ["strict-transport-security", "content-security-policy", "x-frame-options", "referrer-policy"] if h not in headers)
    # tls weak/expired flags (very simple)
    tls_info = summary.get("tls", {})
    tls_weak = 1 if tls_info.get("tls_version") and ("TLSv1" in tls_info.get("tls_version") or tls_info.get("tls_version").startswith("SSL")) else 0
    cert_expired = 0
    cert = tls_info.get("cert") or {}
    not_after = cert.get("notAfter")
    if not_after:
        try:
            # attempt parse (may vary)
            exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            if (exp - datetime.datetime.utcnow()).days < 0:
                cert_expired = 1
        except Exception:
            cert_expired = 0
    reasons = []
    if xp: reasons.append("X-Powered-By present")
    if missing_count: reasons.append(f"Missing security headers: {missing_count}")
    if tls_weak: reasons.append("Weak TLS version")
    if cert_expired: reasons.append("Expired certificate")
    score = xp*10 + missing_count*5 + tls_weak*20 + cert_expired*25
    score = max(0, min(100, score))
    level = "Unlikely Vulnerable" if score < 30 else ("Possibly Vulnerable" if score < 60 else "Likely Vulnerable")
    ml_features = {
        "missing_headers_count": missing_count,
        "x_powered_by_present": xp,
        "tls_weak": tls_weak,
        "cert_expired": cert_expired,
        "http_500_responses": 1 if summary.get("http_headers",{}).get("status_code",0) >= 500 else 0,
        "private_ip": 0
    }
    # detect private IPs if present
    addrs = summary.get("dns", {}).get("addresses", []) or []
    try:
        for a in addrs:
            if ipaddress.ip_address(a).is_private:
                ml_features["private_ip"] = 1
    except Exception:
        pass
    return {"score": score, "level": level, "reasons": reasons, "ml_features": ml_features}

# --- Passive collector wrappers (if you didn't import the real ones, you must paste them here).
# For brevity, we call the assess_website() from previous file, if available.
try:
    from passive_vuln_assessor_ml import assess_website, normalize_url
except Exception:
    # If import fails, define a small stub that raises — user should import original file.
    def assess_website(url, openai_key=None):
        raise RuntimeError("passive_vuln_assessor.assess_website not available. Please import your original file or place functions in this module.")
    def normalize_url(url):
        if not url.startswith(("http://","https://")):
            return "https://" + url
        return url

# --- ML helper: convert ml_features dict to flat row
ML_FEATURE_ORDER = ["missing_headers_count","x_powered_by_present","tls_weak","cert_expired","http_500_responses","private_ip"]

def ml_features_to_row(ml_features):
    return [ ml_features.get(k, 0) for k in ML_FEATURE_ORDER ]

# -----------------------
# Batch assess domains -> save features CSV
# -----------------------
def batch_assess_and_save(domains_file, out_csv, openai_key=None):
    """
    domains_file: one domain or URL per line
    out_csv: path to write CSV of features (entity, timestamp, score, level, reasons, features...)
    """
    rows = []
    with open(domains_file, "r", encoding="utf-8") as f:
        domains = [line.strip() for line in f if line.strip()]
    for d in domains:
        print(f"[+] Assessing {d} ...")
        try:
            res = assess_website(d, openai_key=openai_key)  # returns {"summary":..., "llm_response":...}
        except Exception as e:
            print(f"  ! error assessing {d}: {e}")
            continue
        summary = res.get("summary", {})
        heur = heuristics(summary)  # use the heuristics function (either imported or the local shim)
        ml_features = heur.get("ml_features", {})
        row = {
            "entity": d,
            "timestamp_utc": summary.get("timestamp_utc"),
            "score": heur.get("score"),
            "level": heur.get("level"),
            "reasons": "; ".join(heur.get("reasons", []))
        }
        # add numeric features
        for i, k in enumerate(ML_FEATURE_ORDER):
            row[k] = ml_features.get(k, 0)
        rows.append(row)
    df = pd.DataFrame(rows)
    df.to_csv(out_csv, index=False)
    print(f"[+] Saved features to {out_csv}")
    return df

# -----------------------
# Train Isolation Forest (unsupervised)
# -----------------------
def train_isolation_from_csv(features_csv, model_out="iso_model.joblib"):
    df = pd.read_csv(features_csv)
    if df.empty:
        raise ValueError("Empty features CSV")
    X = df[ML_FEATURE_ORDER].fillna(0).astype(float).values
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
    iso.fit(Xs)
    # persist bundle (scaler + model + sample index)
    joblib.dump({"iso": iso, "scaler": scaler, "features_csv": features_csv}, model_out)
    print(f"[+] Trained IsolationForest and saved to {model_out}")
    return iso, scaler

# -----------------------
# Train XGBoost (supervised) if labeled CSV present
# -----------------------
def train_xgb_from_csv(labeled_csv, model_out="xgb_model.joblib"):
    if not XGBOOST_AVAILABLE:
        raise RuntimeError("XGBoost not installed. pip install xgboost to use supervised training.")
    df = pd.read_csv(labeled_csv)
    if "label" not in df.columns:
        raise ValueError("labeled CSV must contain 'label' column (1 = vulnerable, 0 = normal).")
    X = df[ML_FEATURE_ORDER].fillna(0).astype(float).values
    y = df["label"].astype(int).values
    model = XGBClassifier(n_estimators=200, use_label_encoder=False, eval_metric="logloss", random_state=42)
    model.fit(X, y)
    joblib.dump(model, model_out)
    print(f"[+] Trained XGBoost and saved to {model_out}")
    return model

# -----------------------
# Predict & append flagged vulnerable websites
# -----------------------
def predict_and_track(entity, model_path, out_csv="vulnerable_websites.csv", openai_key=None, mode="unsupervised"):
    """
    Assess a single entity (URL/domain), produce features, run model (iso or xgb),
    and if flagged as vulnerable, append to out_csv (entity,count,score,reason,timestamp).
    """
    res = assess_website(entity, openai_key=openai_key)
    summary = res.get("summary", {})
    heur = heuristics(summary)
    features = heur.get("ml_features", {})
    row = { "entity": entity, "timestamp_utc": summary.get("timestamp_utc"), "score": heur.get("score"),
            "level": heur.get("level"), "reasons": "; ".join(heur.get("reasons", [])) }
    for k in ML_FEATURE_ORDER:
        row[k] = features.get(k, 0)

    # load model
    bundle = joblib.load(model_path)
    flagged = False
    model_type = "unknown"
    if mode == "unsupervised":
        iso = bundle["iso"]; scaler = bundle["scaler"]
        X = np.array([ml_features_to_row(features)], dtype=float)
        Xs = scaler.transform(X)
        pred = iso.predict(Xs)[0]  # -1 anomaly, 1 normal
        score = float(iso.decision_function(Xs)[0])
        row["ml_pred"] = "anomaly" if pred == -1 else "normal"
        row["ml_score"] = score
        if pred == -1:
            flagged = True
        model_type = "isolation_forest"
    else:
        # supervised XGBoost
        model = bundle
        X = np.array([ml_features_to_row(features)], dtype=float)
        pred = int(model.predict(X)[0])
        prob = float(model.predict_proba(X)[0,1]) if hasattr(model, "predict_proba") else None
        row["ml_pred"] = "vulnerable" if pred==1 else "normal"
        row["ml_prob"] = prob
        if pred == 1:
            flagged = True
        model_type = "xgboost"

    # Append to out_csv if flagged
    if flagged:
        out_row = {k: row.get(k) for k in ["entity","timestamp_utc","score","level","reasons","ml_pred","ml_score","ml_prob"] if k in row}
        # load existing
        if os.path.exists(out_csv):
            df_old = pd.read_csv(out_csv)
            df_comb = pd.concat([df_old, pd.DataFrame([out_row])], ignore_index=True)
            # remove duplicates: keep latest
            df_comb.sort_values("timestamp_utc", ascending=False, inplace=True)
            df_comb = df_comb.drop_duplicates("entity", keep="first")
        else:
            df_comb = pd.DataFrame([out_row])
        df_comb.to_csv(out_csv, index=False)
        print(f"[+] Entity {entity} flagged by {model_type} and appended to {out_csv}")
    else:
        print(f"[+] Entity {entity} NOT flagged by {model_type}")
    return row

# -----------------------
# CLI wiring
# -----------------------
def main():
    parser = argparse.ArgumentParser(prog="passive_vuln_assessor_ml")
    sub = parser.add_subparsers(dest="cmd")

    p_batch = sub.add_parser("batch_assess", help="Batch assess domains and save features")
    p_batch.add_argument("domains_file")
    p_batch.add_argument("out_csv")
    p_batch.add_argument("--openai-key", default=None)

    p_train_iso = sub.add_parser("train_iso", help="Train IsolationForest from features CSV")
    p_train_iso.add_argument("features_csv")
    p_train_iso.add_argument("model_out", nargs="?", default="iso_model.joblib")

    p_train_xgb = sub.add_parser("train_xgb", help="Train XGBoost from labeled CSV (label column required)")
    p_train_xgb.add_argument("labeled_csv")
    p_train_xgb.add_argument("model_out", nargs="?", default="xgb_model.joblib")

    p_predict = sub.add_parser("predict_and_track", help="Predict single entity and append vulnerable ones")
    p_predict.add_argument("entity")
    p_predict.add_argument("model_path")
    p_predict.add_argument("out_csv", nargs="?", default="vulnerable_websites.csv")
    p_predict.add_argument("--mode", choices=["unsupervised","supervised"], default="unsupervised")
    p_predict.add_argument("--openai-key", default=None)

    args = parser.parse_args()
    if args.cmd == "batch_assess":
        batch_assess_and_save(args.domains_file, args.out_csv, openai_key=args.openai_key)
    elif args.cmd == "train_iso":
        train_isolation_from_csv(args.features_csv, model_out=args.model_out)
    elif args.cmd == "train_xgb":
        train_xgb_from_csv(args.labeled_csv, model_out=args.model_out)
    elif args.cmd == "predict_and_track":
        predict_and_track(args.entity, args.model_path, out_csv=args.out_csv, openai_key=args.openai_key, mode=args.mode)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
