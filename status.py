import requests
import json
import csv
from datetime import datetime, timezone, timedelta
from pathlib import Path
from config import CLIENT_ID, CLIENT_SECRET, HOST, AUTH_URL

# === Constants ===
FINDINGS_API = f"{HOST}/api/v4/findings"
TOKEN_CACHE_FILE = Path("/tmp/noname_token_status.json")
TOKEN_EXPIRY_HOURS = 8
LIMIT = 100
CSV_FILE = "/tmp/findings_latest_status.csv"
JSON_FILE = "/tmp/findings_latest_status.json"

# === Auth Functions ===

def get_cached_token():
    if TOKEN_CACHE_FILE.exists():
        try:
            with open(TOKEN_CACHE_FILE, "r") as f:
                data = json.load(f)
                token = data["accessToken"]
                timestamp = datetime.fromisoformat(data["timestamp"])
                if datetime.now(timezone.utc) - timestamp < timedelta(hours=TOKEN_EXPIRY_HOURS):
                    print("🔐 Using cached token.")
                    return token
        except Exception as e:
            print("⚠️ Failed to load cached token:", e)
    return None

def cache_token(token):
    with open(TOKEN_CACHE_FILE, "w") as f:
        json.dump({
            "accessToken": token,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }, f)

def get_token():
    token = get_cached_token()
    if token:
        return token

    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }
    try:
        r = requests.post(AUTH_URL, json=payload)
        r.raise_for_status()
        token = r.json().get("accessToken")
        if token:
            cache_token(token)
            return token
    except Exception as e:
        print("❌ Token fetch error:", e)
    return None

# === API Fetch ===

def fetch_latest_statuses(token):
    all_findings = []
    offset = 0
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }

    return_fields = ["id", "title", "status", "severity", "lastUpdate"]

    while True:
        params = {
            "limit": LIMIT,
            "offset": offset,
            "sortDesc": "true"
        }
        for field in return_fields:
            params.setdefault("returnFields", []).append(field)

        response = requests.get(FINDINGS_API, headers=headers, params=params)
        if response.status_code == 401:
            print("🔁 Token expired. Re-authenticating.")
            token = get_token()
            headers["Authorization"] = f"Bearer {token}"
            continue
        elif response.status_code != 200:
            print(f"❌ Failed: {response.status_code} {response.text}")
            break

        data = response.json()
        entities = data.get("entities", [])
        all_findings.extend(entities)
        print(f"📥 Retrieved {len(entities)} (offset={offset})")

        if not data.get("moreEntities"):
            break
        offset += LIMIT

    return all_findings

# === Output Writers ===

def write_to_csv(findings):
    if not findings:
        print("⚠️ No findings to write.")
        return

    keys = ["id", "title", "status", "severity", "lastUpdate"]
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer
