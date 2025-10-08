"""
passive_vuln_assessor.py

Safe, passive vulnerability-likelihood assessor.

What it does (passive only):
 - Resolves DNS A/AAAA records (via socket)
 - Fetches HTTP headers for the root path
 - Fetches /robots.txt and /.well-known/security.txt if present
 - Gets TLS certificate details and TLS protocol used (non-intrusive)
 - Runs heuristic checks for obvious risk factors
 - (Optional) Sends summary to OpenAI for a human-like assessment if API key provided

Usage:
    python passive_vuln_assessor.py https://example.com --openai-key YOUR_KEY
"""

import argparse
import socket
import ssl
import requests
from urllib.parse import urlparse
import datetime
import json
import ipaddress
import sys

# Optional LLM
try:
    import openai
    OPENAI_AVAILABLE = True
except Exception:
    OPENAI_AVAILABLE = False

# -----------------------
# Passive collectors
# -----------------------
def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def fetch_headers(url, timeout=8):
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent":"PassiveAssessor/1.0"})
        return {
            "status_code": resp.status_code,
            "headers": {k.lower(): v for k, v in resp.headers.items()},
            "final_url": resp.url
        }
    except Exception as e:
        return {"error": str(e)}

def fetch_path(base_url, path, timeout=6):
    try:
        resp = requests.get(base_url.rstrip("/") + path, timeout=timeout, headers={"User-Agent":"PassiveAssessor/1.0"})
        return {"status_code": resp.status_code, "text": resp.text[:2000]}
    except Exception as e:
        return {"error": str(e)}

def get_cert_info(hostname, port=443, timeout=6):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=hostname) as ss:
                cert = ss.getpeercert()
                # get negotiated TLS version (py3.8+)
                proto = ss.version()
                return {"cert": cert, "tls_version": proto}
    except Exception as e:
        return {"error": str(e)}

def resolve_hostname(hostname):
    result = {"addresses": []}
    try:
        infos = socket.getaddrinfo(hostname, None)
        addrs = set()
        for fam, socktype, proto, canonname, sockaddr in infos:
            ip = sockaddr[0]
            addrs.add(ip)
        result["addresses"] = list(addrs)
    except Exception as e:
        result["error"] = str(e)
    return result

# -----------------------
# Heuristics
# -----------------------
def heuristics(summary):
    reasons = []
    score = 0

    headers = summary.get("http_headers", {}).get("headers", {}) or {}
    # 1. Server header containing version
    srv = headers.get("server", "")
    if srv:
        # crude: server strings with version numbers look risky if old style
        if "/" in srv or any(ch.isdigit() for ch in srv):
            reasons.append(f"Server header exposed: {srv}")
            score += 15

    # 2. x-powered-by
    xp = headers.get("x-powered-by", "")
    if xp:
        reasons.append(f"X-Powered-By header: {xp}")
        score += 10

    # 3. Missing common security headers (bad)
    missing = []
    for h in ["strict-transport-security", "content-security-policy", "x-frame-options", "referrer-policy"]:
        if h not in headers:
            missing.append(h)
    if missing:
        reasons.append("Missing security headers: " + ", ".join(missing))
        score += len(missing) * 5

    # 4. TLS / cert checks
    cert_info = summary.get("tls", {})
    if cert_info.get("error"):
        reasons.append("TLS certificate info not available / connection failed")
        score += 20
    else:
        tls_version = cert_info.get("tls_version")
        if tls_version:
            if "TLSv1.0" in tls_version or "TLSv1" == tls_version or tls_version.startswith("SSL"):
                reasons.append(f"Weak TLS version negotiated: {tls_version}")
                score += 20
            # Accept TLS1.2/1.3 as fine; small negative score for older
        cert = cert_info.get("cert") or {}
        # expiry
        try:
            not_after = cert.get("notAfter")
            if not_after:
                # certificate date strings vary; try parsing common formats
                try:
                    exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                except Exception:
                    # try without timezone
                    try:
                        exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y")
                    except Exception:
                        exp = None
                if exp:
                    days_left = (exp - datetime.datetime.utcnow()).days
                    if days_left < 0:
                        reasons.append("TLS certificate expired")
                        score += 25
                    elif days_left < 30:
                        reasons.append(f"TLS certificate about to expire in {days_left} days")
                        score += 5
        except Exception:
            pass

    # 5. Response codes and weirdness
    status = summary.get("http_headers", {}).get("status_code")
    if status and isinstance(status, int):
        if status >= 500:
            reasons.append(f"Server returning {status} responses (internal errors)")
            score += 10
        if status == 301 or status == 302:
            # not directly suspicious; no penalty
            pass

    # 6. robots.txt / security.txt presence
    robots = summary.get("robots", {})
    if robots.get("error"):
        # not necessarily bad
        pass
    else:
        if 'disallow' in (robots.get("text","") or "").lower():
            # having disallow is normal
            pass

    sec = summary.get("security_txt", {})
    if not sec or sec.get("error"):
        # absence of security.txt is not a vulnerability but absence may reduce transparency
        pass
    else:
        reasons.append("Found security.txt (good: owner contact found)")
        score -= 5

    # 7. IP reputation hint (passive): large number of addresses from same ASN not checked here.
    # If summary has many addresses (private IPs) we check
    addrs = summary.get("dns", {}).get("addresses", []) or []
    try:
        for a in addrs:
            ip_obj = ipaddress.ip_address(a)
            if ip_obj.is_private:
                reasons.append("Host resolves to a private IP (likely internal or misconfigured)")
                score += 10
    except Exception:
        pass

    # Normalize score to 0-100
    score = max(0, min(100, score))
    if score >= 60:
        level = "Likely Vulnerable"
    elif score >= 30:
        level = "Possibly Vulnerable"
    else:
        level = "Unlikely Vulnerable"

    return {"score": score, "level": level, "reasons": reasons}

# -----------------------
# LLM wrapper (optional)
# -----------------------
SYSTEM_PROMPT = """
You are a security analyst assistant. You WILL NOT provide any exploit instructions or step-by-step attack actions.
Given the passive signals about a website (headers, TLS, robots, DNS), provide:
- A short risk level: Likely Vulnerable / Possibly Vulnerable / Unlikely Vulnerable
- 3 bullet reasons (based only on the supplied signals)
- Immediate safe recommendations (contact owner, patch, enable HSTS, rotate cert)
Be concise and do not suggest any intrusive testing.
"""

LLM_USER_TEMPLATE = "Passive signals JSON:\n\n{data}\n\nAssess the risk level (one of: Likely Vulnerable, Possibly Vulnerable, Unlikely Vulnerable) and give 3 short reasons and safe remediation steps."

def call_llm_assess(summary, openai_api_key, model="gpt-4o-mini"):
    if not OPENAI_AVAILABLE:
        return {"error": "openai library not installed or available locally"}
    openai.api_key = openai_api_key
    payload = SYSTEM_PROMPT + "\n\n" + LLM_USER_TEMPLATE.format(data=json.dumps(summary, default=str, indent=2))
    resp = openai.ChatCompletion.create(
        model=model,
        messages=[
            {"role":"system", "content": SYSTEM_PROMPT},
            {"role":"user", "content": LLM_USER_TEMPLATE.format(data=json.dumps(summary, default=str, indent=2))}
        ],
        temperature=0.0,
        max_tokens=350
    )
    return resp

# -----------------------
# Main routine
# -----------------------
def assess_website(url, openai_key=None):
    url = normalize_url(url)
    parsed = urlparse(url)
    hostname = parsed.hostname
    base = f"{parsed.scheme}://{hostname}"

    summary = {}
    summary["requested_url"] = url
    summary["timestamp_utc"] = datetime.datetime.utcnow().isoformat() + "Z"

    # DNS
    summary["dns"] = resolve_hostname(hostname)

    # TLS/cert
    summary["tls"] = get_cert_info(hostname)

    # HTTP headers (root)
    summary["http_headers"] = fetch_headers(base)

    # robots and security.txt
    summary["robots"] = fetch_path(base, "/robots.txt")
    summary["security_txt"] = fetch_path(base, "/.well-known/security.txt")

    # Heuristics
    heur = heuristics(summary)
    summary["heuristics"] = heur

    # Optional LLM explanation
    llm_resp = None
    if openai_key:
        try:
            llm_resp = call_llm_assess(summary, openai_key)
        except Exception as e:
            llm_resp = {"error": str(e)}

    return {"summary": summary, "llm_response": llm_resp}

# Example CLI entrypoint
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Passive vulnerability likelihood assessor")
    parser.add_argument("url", help="Website URL (e.g. example.com or https://example.com)")
    parser.add_argument("--openai-key", help="OpenAI API key (optional) to get LLM explanation", default=None)
    args = parser.parse_args()

    out = assess_website(args.url, openai_key=args.openai_key)
    print(json.dumps(out, indent=2, default=str))
