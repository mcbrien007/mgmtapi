import argparse
import csv
import json
import logging
import time
import random
import requests
from datetime import datetime, timedelta, timezone
from pathlib import Path
from config import CLIENT_ID, CLIENT_SECRET, HOST, AUTH_URL

# --- Constants ---
TOKEN_CACHE_FILE = Path("/tmp/token_cache.json")
TOKEN_EXPIRY_HOURS = 8
FINDINGS_API = f"{HOST}/api/v4/findings"
CSV_PATH = "/tmp/findings_report.csv"
JSON_PATH = "/tmp/findings_report.json"
LIMIT = 50

# --- Logging setup ---
logging.basicConfig(filename="/tmp/findings_log.txt", level=logging.INFO, format='%(asctime)s - %(message)s')


def get_cached_token():
    if TOKEN_CACHE_FILE.exists():
        with open(TOKEN_CACHE_FILE, "r") as f:
            try:
                data = json.load(f)
                token = data.get("accessToken")
                timestamp = data.get("timestamp")
                if token and timestamp:
                    token_time = datetime.fromisoformat(timestamp)
                    if datetime.now(timezone.utc) - token_time < timedelta(hours=TOKEN_EXPIRY_HOURS):
                        print("🔐 Using cached token.")
                        return token
            except (json.JSONDecodeError, ValueError):
                print("⚠️ Failed to parse cached token.")
    return None


def cache_token(token):
    with open(TOKEN_CACHE_FILE, "w") as f:
        json.dump({
            "accessToken": token,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }, f)


def get_bearer_token(force_refresh=False):
    if not force_refresh:
        cached = get_cached_token()
        if cached:
            return cached

    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }

    try:
        response = requests.post(AUTH_URL, json=payload)
        if response.status_code in [200, 201]:
            token = response.json().get("accessToken")
            if token:
                cache_token(token)
                return token
        print(f"❌ Token fetch failed: {response.status_code} - {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Auth error: {e}")
    return None


def build_headers(token):
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }


def retry_request(method, url, headers, params=None, retries=5):
    global BEARER_TOKEN
    for attempt in range(retries):
        try:
            response = getattr(requests, method)(url, headers=headers, params=params)
            if response.status_code in [200]:
                return response
            elif response.status_code == 401:
                print("🔁 Token expired. Refreshing.")
                BEARER_TOKEN = get_bearer_token(force_refresh=True)
                headers["Authorization"] = f"Bearer {BEARER_TOKEN}"
                time.sleep(1.5)
                continue
            else:
                print(f"❗ Request failed ({response.status_code}): {response.text}")
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error: {e}")
        time.sleep((2 ** attempt) + random.uniform(0, 1))
    return None


def get_time_window(start_arg, end_arg, hours_back=24):
    now = datetime.now(timezone.utc)
    if start_arg and end_arg:
        return start_arg, end_arg
    end_time = now
    start_time = now - timedelta(hours=hours_back)
    return start_time.isoformat(), end_time.isoformat()


def fetch_findings(start_time, end_time):
    findings = []
    offset = 0

    return_fields = [
        "id", "title", "url", "typeId", "apiId", "module", "host", "path", "method",
        "resourceGroupName", "status", "severity", "owaspTags", "complianceFrameworkTags",
        "vulnerabilityFrameworkTags", "detectionTime", "lastUpdate", "triggeredOn",
        "description", "impact", "remediation", "investigate", "comments", "tickets",
        "externalTickets", "evidence", "source", "hasRelatedIncidents", "tagsIds",
        "relatedApiIds"
    ]

    while True:
        params = {
            "sortDesc": "true",
            "limit": LIMIT,
            "offset": offset,
            "detectionStartDate": start_time,
            "detectionEndDate": end_time,
            "lastUpdateStartDate": start_time,
            "lastUpdateEndDate": end_time
        }
        for field in return_fields:
            params["returnFields"] = params.get("returnFields", []) + [field]

        response = retry_request("get", FINDINGS_API, build_headers(BEARER_TOKEN), params=params)
        if not response:
            break

        data = response.json()
        entities = data.get("entities", [])
        findings.extend(entities)
        print(f"📥 Retrieved {len(entities)} findings (offset {offset})")
        if not data.get("moreEntities"):
            break
        offset += LIMIT
    return findings


def flatten_finding(finding):
    return {
        "id": finding.get("id"),
        "title": finding.get("title"),
        "url": finding.get("url"),
        "severity": finding.get("severity"),
        "status": finding.get("status"),
        "host": finding.get("host"),
        "path": finding.get("path"),
        "method": finding.get("method"),
        "detectionTime": finding.get("detectionTime"),
        "lastUpdate": finding.get("lastUpdate"),
        "source": ", ".join(finding.get("source", [])),
        "owaspTags": ", ".join(finding.get("owaspTags", [])),
        "typeId": finding.get("typeId")
    }


def write_findings_to_csv(findings, output_path=CSV_PATH):
    if not findings:
        print("⚠️ No findings to write to CSV.")
        return

    flattened = [flatten_finding(f) for f in findings]
    keys = flattened[0].keys()

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(flattened)

    print(f"✅ CSV written to: {output_path}")


def write_findings_to_json(findings, output_path=JSON_PATH):
    if not findings:
        print("⚠️ No findings to write to JSON.")
        return

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    print(f"✅ JSON written to: {output_path}")


# --- MAIN ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch findings from Noname API")
    parser.add_argument("--start", help="Start ISO timestamp (UTC)", default=None)
    parser.add_argument("--end", help="End ISO timestamp (UTC)", default=None)
    parser.add_argument("--hours", help="Hours back if no start/end", type=int, default=24)
    args = parser.parse_args()

    BEARER_TOKEN = get_bearer_token()
    if not BEARER_TOKEN:
        raise SystemExit("❌ Failed to authenticate.")

    start, end = get_time_window(args.start, args.end, args.hours)
    print(f"📅 Fetching findings from: {start} to {end}")

    findings = fetch_findings(start, end)

    write_findings_to_csv(findings)
    write_findings_to_json(findings)
    print(f"📊 Total findings: {len(findings)}")
