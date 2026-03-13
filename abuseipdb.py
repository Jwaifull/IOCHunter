import requests

BASE_URL = "https://api.abuseipdb.com/api/v2"


def query(ioc: str, ioc_type: str, api_key: str) -> dict:
    if not api_key:
        return {"error": "No API key configured", "source": "AbuseIPDB"}

    if ioc_type not in ("IPv4", "IPv6"):
        return {"source": "AbuseIPDB", "skipped": True, "reason": "Only supports IPs"}

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ioc, "maxAgeInDays": 90, "verbose": True}

    try:
        r = requests.get(f"{BASE_URL}/check", headers=headers, params=params, timeout=10)

        if r.status_code == 401:
            return {"error": "Invalid API key", "source": "AbuseIPDB"}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}", "source": "AbuseIPDB"}

        data = r.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)

        return {
            "source": "AbuseIPDB",
            "found": True,
            "abuse_score": score,
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "domain": data.get("domain", ""),
            "is_tor": data.get("isTor", False),
            "risk": _risk_level(score),
        }

    except requests.exceptions.Timeout:
        return {"error": "Timeout", "source": "AbuseIPDB"}
    except Exception as e:
        return {"error": str(e), "source": "AbuseIPDB"}


def _risk_level(score):
    if score == 0:
        return "Clean"
    elif score < 25:
        return "Low"
    elif score < 50:
        return "Medium"
    elif score < 75:
        return "High"
    else:
        return "Critical"
