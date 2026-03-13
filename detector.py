import re

# Regex patterns
PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "ipv6": re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|"
        r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|"
        r"\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"
    ),
    "url": re.compile(
        r"https?://[^\s\"'<>]+"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|edu|gov|io|co|info|biz|xyz|top|club|site|online|ru|cn|de|uk|fr|br|jp|kr|in|tk|ml|ga|cf|gq|live|tech|app|dev|cloud|pro|pw|cc|tv|me|us|ca|au|nz|sg|my)\b",
        re.IGNORECASE
    ),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "email": re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
}

# Private/reserved IP ranges to skip
PRIVATE_RANGES = re.compile(
    r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.|255\.|169\.254\.)"
)


def detect_single(value: str) -> str | None:
    """Detect IOC type for a single value."""
    value = value.strip()
    if not value:
        return None

    if PATTERNS["cve"].match(value):
        return "CVE"
    if PATTERNS["email"].match(value):
        return "Email"
    if PATTERNS["url"].match(value):
        return "URL"
    if PATTERNS["sha256"].fullmatch(value):
        return "SHA256"
    if PATTERNS["sha1"].fullmatch(value):
        return "SHA1"
    if PATTERNS["md5"].fullmatch(value):
        return "MD5"
    if PATTERNS["ipv6"].match(value):
        return "IPv6"
    if PATTERNS["ipv4"].fullmatch(value):
        return "IPv4"
    if PATTERNS["domain"].fullmatch(value):
        return "Domain"
    return None


def extract_from_text(text: str) -> list[dict]:
    """Extract all IOCs from raw text (logs, etc.)."""
    found = {}

    # Order matters: more specific first
    TYPE_DISPLAY = {
        "ipv4": "IPv4", "ipv6": "IPv6", "url": "URL",
        "domain": "Domain", "md5": "MD5", "sha1": "SHA1",
        "sha256": "SHA256", "email": "Email", "cve": "CVE",
    }

    for ioc_type in ["cve", "email", "url", "sha256", "sha1", "md5", "ipv6", "ipv4", "domain"]:
        for match in PATTERNS[ioc_type].finditer(text):
            val = match.group().strip()

            # Skip private IPs
            if ioc_type == "ipv4" and PRIVATE_RANGES.match(val):
                continue

            # Skip if already found as a more specific type
            if val not in found:
                found[val] = TYPE_DISPLAY.get(ioc_type, ioc_type.upper())

    result = [{"value": k, "type": v} for k, v in found.items()]
    return result


def parse_input(raw: str) -> list[dict]:
    """
    Parse user input — could be:
    - One IOC per line
    - Raw log text
    """
    lines = [l.strip() for l in raw.strip().splitlines() if l.strip()]
    iocs = []
    seen = set()

    for line in lines:
        ioc_type = detect_single(line)
        if ioc_type and line not in seen:
            seen.add(line)
            iocs.append({"value": line, "type": ioc_type})

    # If very few detected from line-by-line, try full extraction
    if len(iocs) < 2 and len(raw) > 100:
        extracted = extract_from_text(raw)
        for item in extracted:
            if item["value"] not in seen:
                seen.add(item["value"])
                iocs.append(item)

    return iocs
