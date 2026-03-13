import requests
import time
import os
import datetime

BASE_URL = "https://otx.alienvault.com/api/v1"
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alienvault_debug.log")

def _log(msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except:
        pass

def query(ioc: str, ioc_type: str, api_key: str) -> dict:
    if not api_key:
        return {"error": "No API key configured", "source": "AlienVault OTX"}

    headers = {"X-OTX-API-KEY": api_key}

    if ioc_type in ("IPv4", "IPv6"):
        url = f"{BASE_URL}/indicators/IPv4/{ioc}/general"
    elif ioc_type == "Domain":
        url = f"{BASE_URL}/indicators/domain/{ioc}/general"
    elif ioc_type == "URL":
        url = f"{BASE_URL}/indicators/url/{ioc}/general"
    elif ioc_type in ("MD5", "SHA1", "SHA256"):
        url = f"{BASE_URL}/indicators/file/{ioc}/general"
    elif ioc_type == "CVE":
        url = f"{BASE_URL}/indicators/cve/{ioc}/general"
    else:
        return {"source": "AlienVault OTX", "skipped": True}

    _log(f"START query: {ioc_type} {ioc}")
    start = time.time()

    try:
        session = requests.Session()
        session.headers.update(headers)
        r = session.get(url, timeout=8)
        elapsed = time.time() - start
        _log(f"Response in {elapsed:.2f}s — HTTP {r.status_code}")

        if r.status_code == 401:
            return {"error": "Invalid API key", "source": "AlienVault OTX"}
        if r.status_code == 404:
            return {"source": "AlienVault OTX", "found": False, "pulse_count": 0, "risk": "Clean"}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}", "source": "AlienVault OTX"}

        data = r.json()
        pulse_info = data.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        _log(f"SUCCESS — pulses: {pulse_count}")

        pulses = pulse_info.get("pulses", [])
        tags = []
        for p in pulses[:5]:
            tags.extend(p.get("tags", []))
        tags = list(set(tags))[:10]

        return {
            "source": "AlienVault OTX",
            "found": True,
            "pulse_count": pulse_count,
            "tags": tags,
            "country": data.get("country_name", ""),
            "risk": _risk_level(pulse_count),
        }

    except requests.exceptions.Timeout:
        elapsed = time.time() - start
        _log(f"Timeout after {elapsed:.1f}s — OTX unreachable from this network")
        return {
            "source": "AlienVault OTX",
            "skipped": True,
            "reason": "OTX unreachable from this network — use curl to query manually"
        }

    except requests.exceptions.ConnectionError as e:
        _log(f"Connection error: {e}")
        return {"error": "Connection error", "source": "AlienVault OTX"}

    except Exception as e:
        _log(f"Exception: {type(e).__name__}: {e}")
        return {"error": str(e)[:80], "source": "AlienVault OTX"}


def _risk_level(pulse_count):
    if pulse_count == 0:
        return "Clean"
    elif pulse_count < 3:
        return "Low"
    elif pulse_count < 10:
        return "Medium"
    elif pulse_count < 25:
        return "High"
    else:
        return "Critical"
