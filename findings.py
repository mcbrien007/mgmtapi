#!/usr/bin/env python3
"""
Fetch findings from Noname API, enrich each finding with API metadata (from apiId and relatedApiIds),
then save results to JSON and CSV.

Summary of Your Findings Fetcher Script
Authentication & Token Caching

Authenticates to Noname API using client_id and client_secret.

Caches the Bearer token locally for up to 8 hours to avoid redundant auth calls.

Fetch Findings

Queries the findings API within a specified time window (--start and --end or --hours back).

Requests a comprehensive set of fields (returnFields) for each finding.

Handles pagination with offset and limit.

Retries on network or auth errors with exponential backoff.

API Metadata Enrichment

For each finding, collects its apiId and all relatedApiIds.

Fetches detailed API metadata for each unique API ID.

Adds this API metadata as a list under "apiDetails" inside each finding.

Output Formats

Writes enriched findings with full API metadata to JSON.

Writes a flattened CSV summary containing all requested fields plus a count of API metadata entries per finding.

Properly formats arrays and dicts in CSV for readability.

Logging and Error Handling

Logs token and request activity.

Prints clear error messages for failed requests.

Handles token expiration transparently by refreshing.

Key Benefits
Comprehensive Data: Fetches detailed findings and enriches them with related API details.

Efficiency: Avoids redundant API metadata calls by caching seen API IDs in-memory per run.

Flexible: Accepts time ranges or hours back via CLI arguments.

User-friendly Output: JSON for full detail and CSV for easy spreadsheet analysis.

Robust: Retries on transient errors and handles token expiration automatically.


"""

import argparse
import csv
import json
import logging
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, List, Dict

import requests

# ── Configuration ──────────────────────────────────────────────────────────────
from config import CLIENT_ID, CLIENT_SECRET, HOST, AUTH_URL

TOKEN_CACHE_FILE = Path("/tmp/token_cache.json")
TOKEN_EXPIRY_HOURS = 8

FINDINGS_API = f"{HOST}/api/v4/findings"
CSV_PATH = "/tmp/findings_report.csv"
JSON_PATH = "/tmp/findings_report.json"
LIMIT = 50

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    filename="/tmp/findings_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)

RETURN_FIELDS = [
    "id", "title", "url", "typeId", "apiId", "module", "host", "path", "method",
    "resourceGroupName", "status", "severity", "owaspTags", "complianceFrameworkTags",
    "vulnerabilityFrameworkTags", "detectionTime", "lastUpdate", "triggeredOn",
    "description", "impact", "remediation", "investigate", "comments", "tickets",
    "externalTickets", "evidence", "source", "hasRelatedIncidents", "tagsIds",
    "relatedApiIds"
]


def get_cached_token() -> Optional[str]:
    if TOKEN_CACHE_FILE.exists():
        try:
            with TOKEN_CACHE_FILE.open("r") as f:
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


def cache_token(token: str) -> None:
    with TOKEN_CACHE_FILE.open("w") as f:
        json.dump({
            "accessToken": token,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }, f)


def get_bearer_token(force_refresh: bool = False) -> Optional[str]:
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


def build_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }


def retry_request(method: str, url: str, headers: dict, params: Optional[dict] = None, retries: int = 5) -> Optional[requests.Response]:
    global BEARER_TOKEN
    for attempt in range(retries):
        try:
            response = getattr(requests, method)(url, headers=headers, params=params)
            if response.status_code == 200:
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


def get_time_window(start_arg: Optional[str], end_arg: Optional[str], hours_back: int = 24):
    now = datetime.now(timezone.utc)
    if start_arg and end_arg:
        return start_arg, end_arg
    end_time = now
    start_time = now - timedelta(hours=hours_back)
    return start_time.isoformat(), end_time.isoformat()


def fetch_findings(start_time: str, end_time: str) -> List[dict]:
    findings = []
    offset = 0

    while True:
        params = {
            "sortDesc": "true",
            "limit": LIMIT,
            "offset": offset,
            "detectionStartDate": start_time,
            "detectionEndDate": end_time,
            "lastUpdateStartDate": start_time,
            "lastUpdateEndDate": end_time,
            "returnFields": RETURN_FIELDS
        }

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


def fetch_api_metadata(api_id: str, token: str) -> Optional[dict]:
    url = f"{HOST}/api/v3/apis/{api_id}"
    headers = build_headers(token)
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"⚠️ Failed to fetch API {api_id}: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"❌ API fetch error for {api_id}: {e}")
    return None


def stringify(value):
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    elif isinstance(value, dict):
        return json.dumps(value)
    return value


def flatten_finding(finding: dict) -> dict:
    # Flatten all RETURN_FIELDS + flatten apiDetails summary (just API ids count)
    flat = {field: stringify(finding.get(field)) for field in RETURN_FIELDS}
    # Add a summary field for how many APIs detailed
    if "apiDetails" in finding:
        flat["apiDetailsCount"] = len(finding["apiDetails"])
    else:
        flat["apiDetailsCount"] = 0
    return flat


def write_findings_to_csv(findings: List[dict], output_path: str = CSV_PATH) -> None:
    if not findings:
        print("⚠️ No findings to write to CSV.")
        return

    flattened = [flatten_finding(f) for f in findings]
    keys = RETURN_FIELDS + ["apiDetailsCount"]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(flattened)

    print(f"✅ CSV written to: {output_path}")


def write_findings_to_json(findings: List[dict], output_path: str = JSON_PATH) -> None:
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

    raw_findings = fetch_findings(start, end)

    # Enrich findings with API metadata
    enriched_findings = []
    seen_api_ids = set()
    for finding in raw_findings:
        api_ids = set()
        if finding.get("apiId"):
            api_ids.add(finding["apiId"])
        for rid in finding.get("relatedApiIds", []):
            api_ids.add(rid)

        api_details = []
        for api_id in api_ids:
            if api_id not in seen_api_ids:
                metadata = fetch_api_metadata(api_id, BEARER_TOKEN)
                if metadata:
                    api_details.append(metadata)
                seen_api_ids.add(api_id)
        finding["apiDetails"] = api_details
        enriched_findings.append(finding)

    write_findings_to_csv(enriched_findings)
    write_findings_to_json(enriched_findings)
    print(f"📊 Total findings: {len(enriched_findings)}")
