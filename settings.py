import json
import os

CONFIG_FILE = os.path.join(os.path.expanduser("~"), ".iochunter_config.json")

DEFAULT_CONFIG = {
    "api_keys": {
        "virustotal": "",
        "abuseipdb": "",
        "alienvault": "",
        "ipinfo": "",
        "greynoise": "",
        "malwarebazaar": "",
        "urlscan": "",
        "threatfox": "",
        "shodan": "",
        "hybrid_analysis": "",
        "securitytrails": "",
    },
    "ai_enabled": False,
    "ai_host": "http://localhost:11434",
    "ai_model": "qwen2.5:7b",
    "theme": "dark",
}


def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                data = json.load(f)
                # Merge with defaults in case new keys were added
                for key, value in DEFAULT_CONFIG.items():
                    if key not in data:
                        data[key] = value
                    elif isinstance(value, dict):
                        for k, v in value.items():
                            if k not in data[key]:
                                data[key][k] = v
                return data
        except Exception:
            return DEFAULT_CONFIG.copy()
    return DEFAULT_CONFIG.copy()


def save_config(config):
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        return False


def get_api_key(name):
    config = load_config()
    return config.get("api_keys", {}).get(name, "")
