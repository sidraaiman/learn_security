import re
import hashlib
from collections import defaultdict
from datetime import datetime

# Regex for Apache/Nginx common log format:
# Example: 192.168.1.10 - - [08/Oct/2025:10:12:01 +0000] "GET /login.php HTTP/1.1" 200 532 "-" "Mozilla/5.0"
log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s'                  # Client IP
    r'.*\[(?P<time>[^\]]+)\]\s'                      # Timestamp
    r'"(?P<method>GET|POST|PUT|DELETE|HEAD)\s'       # HTTP Method
    r'(?P<url>[^\s]+).*"\s'                          # URL/Path
    r'\d+\s\d+\s"[^"]*"\s"(?P<useragent>[^"]*)"'     # User-Agent
)

# Function to normalize timestamp
def parse_time(timestr):
    return datetime.strptime(timestr.split()[0], "%d/%b/%Y:%H:%M:%S")

# Storage for parsed logs
logs = []

# Load log file
with open("apache_log_10000.log", "r") as f:
    for line in f:
        match = log_pattern.match(line)
        if match:
            data = match.groupdict()
            logs.append({
                "ip": data["ip"],
                "time": parse_time(data["time"]),
                "method": data["method"],
                "url": data["url"],
                "useragent": data["useragent"]
            })

# Group logs by IP + URL
groups = defaultdict(list)
for log in logs:
    groups[(log["ip"], log["url"])].append(log)

# Generate Trace IDs and detect suspicious behavior
results = []
for (ip, url), entries in groups.items():
    entries = sorted(entries, key=lambda x: x["time"])
    first_seen = entries[0]["time"]
    last_seen = entries[-1]["time"]
    method = entries[0]["method"]
    useragent = entries[0]["useragent"]
    count = len(entries)

    # Generate Trace ID
    rand_hash = hashlib.md5((ip + str(first_seen)).encode()).hexdigest()[:4]
    trace_id = f"TRACE-{ip}-{first_seen.strftime('%Y%m%dT%H%M%S')}-{rand_hash}"

    # Detect suspicious activity
    notes = ""
    if count > 20:
        notes = "High request rate (possible brute-force or DDoS)"
    if "/admin" in url.lower() or "/login" in url.lower():
        notes += " | Sensitive endpoint hit"

    results.append({
        "TraceID": trace_id,
        "IP": ip,
        "URL": url,
        "Method": method,
        "User-Agent": useragent,
        "Requests": count,
        "First Seen": first_seen,
        "Last Seen": last_seen,
        "Notes": notes.strip(" |")
    })

# Sort by number of requests (descending)
results = sorted(results, key=lambda x: x["Requests"], reverse=True)

# Print in table format
print(f"{'Trace ID':<40} {'IP':<15} {'URL':<20} {'Method':<6} {'Requests':<8} {'First Seen':<20} {'Last Seen':<20} {'Notes'}")
print("-"*130)
for r in results:
    print(f"{r['TraceID']:<40} {r['IP']:<15} {r['URL']:<20} {r['Method']:<6} {r['Requests']:<8} "
          f"{r['First Seen']} {r['Last Seen']} {r['Notes']}")
#Log file → Parse with regex → Group by IP/URL → Count requests → Generate Trace ID → Detect suspicious activity → Print in table.