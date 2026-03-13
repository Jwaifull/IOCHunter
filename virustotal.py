import requests

BASE_URL = "https://www.virustotal.com/api/v3"


def query(ioc: str, ioc_type: str, api_key: str) -> dict:
    if not api_key:
        return {"error": "No API key configured", "source": "VirusTotal"}

    headers = {"x-apikey": api_key}

    try:
        if ioc_type in ("IPv4", "IPv6"):
            url = f"{BASE_URL}/ip_addresses/{ioc}"
        elif ioc_type == "Domain":
            url = f"{BASE_URL}/domains/{ioc}"
        elif ioc_type == "URL":
            import base64
            ioc_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            url = f"{BASE_URL}/urls/{ioc_id}"
        elif ioc_type in ("MD5", "SHA1", "SHA256"):
            url = f"{BASE_URL}/files/{ioc}"
        else:
            return {"error": f"Type {ioc_type} not supported", "source": "VirusTotal"}

        r = requests.get(url, headers=headers, timeout=10)

        if r.status_code == 404:
            return {"source": "VirusTotal", "found": False, "malicious": 0, "total": 0, "score": "Not found"}
        if r.status_code == 401:
            return {"error": "Invalid API key", "source": "VirusTotal"}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}", "source": "VirusTotal"}

        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        return {
            "source": "VirusTotal",
            "found": True,
            "malicious": malicious,
            "suspicious": suspicious,
            "total": total,
            "score": f"{malicious}/{total}",
            "risk": _risk_level(malicious, total),
            "tags": data.get("tags", []),
            "country": data.get("country", ""),
        }

    except requests.exceptions.Timeout:
        return {"error": "Timeout", "source": "VirusTotal"}
    except Exception as e:
        return {"error": str(e), "source": "VirusTotal"}


def _risk_level(malicious, total):
    if total == 0:
        return "Unknown"
    ratio = malicious / total
    if malicious == 0:
        return "Clean"
    elif ratio < 0.1:
        return "Low"
    elif ratio < 0.3:
        return "Medium"
    elif ratio < 0.6:
        return "High"
    else:
        return "Critical"
