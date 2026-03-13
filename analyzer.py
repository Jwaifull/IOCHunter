import concurrent.futures
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import virustotal, abuseipdb, alienvault, ipinfo
from settings import get_api_key, load_config

API_MAP = {
    "IPv4":   ["virustotal", "abuseipdb", "alienvault", "ipinfo"],
    "IPv6":   ["virustotal", "abuseipdb", "alienvault", "ipinfo"],
    "Domain": ["virustotal", "alienvault"],
    "URL":    ["virustotal", "alienvault"],
    "MD5":    ["virustotal", "alienvault"],
    "SHA1":   ["virustotal", "alienvault"],
    "SHA256": ["virustotal", "alienvault"],
    "Email":  ["abuseipdb"],
    "CVE":    ["alienvault"],
}

API_MODULES = {
    "virustotal": virustotal,
    "abuseipdb": abuseipdb,
    "alienvault": alienvault,
    "ipinfo": ipinfo,
}

RISK_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Clean": 0, "Unknown": 0}


def analyze_ioc(ioc_value, ioc_type):
    apis_to_call = API_MAP.get(ioc_type, [])
    config = load_config()
    results = {}

    def call_api(api_name):
        module = API_MODULES.get(api_name)
        if not module:
            return api_name, {"error": "Module not found", "source": api_name}
        key = config.get("api_keys", {}).get(api_name, "")
        result = module.query(ioc_value, ioc_type, key)
        return api_name, result

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = {executor.submit(call_api, api): api for api in apis_to_call}
        for future in concurrent.futures.as_completed(futures):
            try:
                api_name, result = future.result()
                results[api_name] = result
            except Exception as e:
                api_name = futures[future]
                results[api_name] = {"error": str(e), "source": api_name}

    overall_risk = _calculate_overall_risk(results)
    return {"value": ioc_value, "type": ioc_type, "overall_risk": overall_risk, "results": results}


def analyze_batch(iocs, progress_callback=None):
    analyzed = []
    total = len(iocs)
    for i, ioc in enumerate(iocs):
        result = analyze_ioc(ioc["value"], ioc["type"])
        analyzed.append(result)
        if progress_callback:
            progress_callback(i + 1, total)
    return analyzed


def _calculate_overall_risk(results):
    max_risk = "Unknown"
    max_score = -1
    for api_result in results.values():
        risk = api_result.get("risk", "Unknown")
        score = RISK_ORDER.get(risk, 0)
        if score > max_score:
            max_score = score
            max_risk = risk
    return max_risk
