# 🔍 IOCHunter

**Open Source Threat Intelligence Analyzer for Incident Responders**

IOCHunter is a lightweight, portable desktop tool for analyzing Indicators of Compromise (IOCs) against multiple threat intelligence APIs simultaneously. Designed for security consultants and incident responders who need fast answers in the field.

---

## ✨ Features

- 🔍 **Auto-detection** of IOC type — IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256, Email, CVE
- ⚡ **Parallel API queries** — all sources queried simultaneously
- 📋 **Multiple input methods** — paste manually, upload .txt/.csv/.log, or paste raw logs
- 📊 **Risk scoring** — consolidated risk level per IOC (Critical / High / Medium / Low / Clean)
- 📄 **Export** — PDF and HTML reports with professional styling
- ⚙️ **User-managed API keys** — stored locally, never shared
- 🤖 **AI mode** (optional) — Qwen via Ollama for log parsing and result synthesis
- 🖥️ **Cross-platform** — Windows and Linux

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/Jwaifull/IOCHunter.git
cd IOCHunter
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

> Python 3.10 or higher required.

### 3. Run

```bash
python main.py
```

---

## 📦 Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| customtkinter | 5.2.2 | Modern GUI framework |
| requests | 2.31.0 | HTTP API calls |
| reportlab | 4.1.0 | PDF export |
| jinja2 | 3.1.3 | HTML report templating |
| Pillow | 10.2.0 | Image handling |

Install all at once:
```bash
pip install -r requirements.txt
```

---

## 🔑 API Keys Setup

IOCHunter requires free API keys from each service. Go to **Settings → API Keys** in the app to enter them.

| Service | Free Tier | Sign Up |
|---------|-----------|---------|
| VirusTotal | 500 req/day | https://virustotal.com |
| AbuseIPDB | 1,000 req/day | https://abuseipdb.com |
| AlienVault OTX | Unlimited | https://otx.alienvault.com |
| IPinfo | 50,000 req/month | https://ipinfo.io |
| GreyNoise | Limited | https://greynoise.io |
| MalwareBazaar | Unlimited | https://bazaar.abuse.ch |
| URLScan.io | Unlimited | https://urlscan.io |
| ThreatFox | Unlimited | https://threatfox.abuse.ch |
| Shodan | Limited | https://shodan.io |
| Hybrid Analysis | Unlimited | https://hybrid-analysis.com |

> Keys are saved locally at `~/.iochunter_config.json` on your machine.

---

## 📖 Supported IOC Types

| Type | Example |
|------|---------|
| IPv4 | `45.33.32.156` |
| IPv6 | `2001:db8::1` |
| Domain | `evil-domain.com` |
| URL | `http://evil.com/payload.exe` |
| MD5 | `d41d8cd98f00b204e9800998ecf8427e` |
| SHA1 | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| SHA256 | `e3b0c44298fc1c149afb4c8996fb92427ae41e4...` |
| Email | `attacker@evil.com` |
| CVE | `CVE-2024-1234` |

---

## 🗂️ Project Structure

```
IOCHunter/
├── main.py                  # Entry point
├── requirements.txt
├── README.md
├── config/
│   └── settings.py          # Config & API key management
├── modules/
│   ├── detector.py          # IOC type detection (regex)
│   ├── analyzer.py          # Orchestrates API calls
│   └── apis/
│       ├── virustotal.py
│       ├── abuseipdb.py
│       ├── alienvault.py
│       └── ipinfo.py
├── ui/
│   └── main_app.py          # Full GUI (CustomTkinter)
└── exports/
    ├── html_export.py
    └── pdf_export.py
```

---

## 🗺️ Roadmap

- [x] Phase 1 — Core: VirusTotal, AbuseIPDB, AlienVault, IPinfo
- [ ] Phase 2 — GreyNoise, MalwareBazaar, URLScan, ThreatFox
- [ ] Phase 3 — Shodan, Hybrid Analysis, SecurityTrails
- [ ] Phase 4 — AI integration (Qwen via Ollama)
- [ ] Phase 5 — Web interface (FastAPI)
- [ ] Phase 6 — Windows installer (.exe)

---

## 🤝 Contributing

Pull requests are welcome. For major changes, open an issue first.

1. Fork the repo
2. Create your feature branch: `git checkout -b feature/new-api`
3. Commit your changes
4. Push and open a PR

---

## 📄 License

AGPL-3.0 License — free for open source use. For commercial licensing.

---

*Built for the security community by the security community.*
