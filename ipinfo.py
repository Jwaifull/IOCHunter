import requests

BASE_URL = "https://ipinfo.io"


def query(ioc: str, ioc_type: str, api_key: str) -> dict:
    if ioc_type not in ("IPv4", "IPv6"):
        return {"source": "IPinfo", "skipped": True, "reason": "Only supports IPs"}

    try:
        params = {}
        if api_key:
            params["token"] = api_key

        r = requests.get(f"{BASE_URL}/{ioc}/json", params=params, timeout=10)

        if r.status_code == 401:
            return {"error": "Invalid API key", "source": "IPinfo"}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}", "source": "IPinfo"}

        data = r.json()

        return {
            "source": "IPinfo",
            "found": True,
            "country": data.get("country", ""),
            "city": data.get("city", ""),
            "region": data.get("region", ""),
            "org": data.get("org", ""),
            "hostname": data.get("hostname", ""),
            "timezone": data.get("timezone", ""),
            "is_bogon": data.get("bogon", False),
        }

    except requests.exceptions.Timeout:
        return {"error": "Timeout", "source": "IPinfo"}
    except Exception as e:
        return {"error": str(e), "source": "IPinfo"}
