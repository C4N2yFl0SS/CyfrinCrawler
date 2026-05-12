<div align="center">

```
 ________      ___    ___ ________ ________  ___  ________      
|\   ____\    |\  \  /  /|\  _____\\   __  \|\  \|\   ___  \    
\ \  \___|    \ \  \/  / | \  \__/\ \  \|\  \ \  \ \  \\ \  \   
 \ \  \        \ \    / / \ \   __\\ \   _  _\ \  \ \  \\ \  \  
  \ \  \____    \/   / /   \ \  \_| \ \  \\  \\ \  \ \  \\ \  \ 
   \ \_______\__/   / /     \ \__\   \ \__\\ _\\ \__\ \__\\ \__\
    \|_______|\____/ /       \|__|    \|__|\|__|\|__|\|__| \|__|
             \|____|/                                           
                                                                                                
```

# CYFRIN CRAWLER v2.0

**Unlimited Depth · Auto-Stop · Sensitive Intel Engine**

[![Python](https://img.shields.io/badge/Python-3.8%2B-red?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Async](https://img.shields.io/badge/Async-aiohttp-crimson?style=for-the-badge&logo=python&logoColor=white)](https://docs.aiohttp.org)
[![License](https://img.shields.io/badge/License-MIT-darkred?style=for-the-badge)](LICENSE)
[![Author](https://img.shields.io/badge/Author-Jannatul%20Islam-black?style=for-the-badge&logo=github)](https://github.com/C4N2yFl0SS)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

<br/>

> **⚠️ DISCLAIMER:** This tool is intended for **authorized penetration testing, security research, and educational purposes only**. Never run against targets without explicit written permission. The author is not responsible for any misuse or damage caused by this tool. Always comply with applicable laws and regulations.

</div>

---

## 🕷️ Overview

**CYFRIN CRAWLER** is a high-performance, asynchronous web crawler built for security professionals and penetration testers. It recursively maps websites at unlimited depth, automatically stops when complete, and runs a powerful **Sensitive Intel Engine** that detects exposed credentials, API keys, misconfigurations, and hundreds of other security-critical patterns in real time.

```
Target → Crawl → Scan → Report
  ↓         ↓       ↓        ↓
URL      50 concurrent    400+ patterns    TXT + JSON
input    async workers    intel engine     output
```

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔍 Crawling Engine

- ⚡ **50 concurrent async workers** via `aiohttp`
- ♾️ **Unlimited crawl depth** — no artificial caps
- 🛑 **Smart auto-stop** — halts when queue empties
- 🌐 **Full subdomain coverage** of target base domain
- 📡 **Bloom filter deduplication** (5M capacity, 0.1% error rate)
- 🔄 **Automatic retry with backoff** (3 retries, exponential)
- 🔀 **User-Agent rotation** (7 agents including Googlebot)

</td>
<td width="50%">

### 🧠 Intel Engine

- 🔑 **400+ regex patterns** across 15+ categories
- 🔴 CRITICAL / 🟠 HIGH / 🟡 MEDIUM severity classification
- 🔐 Detects: AWS keys, JWT tokens, GitHub PATs, OpenAI keys
- 🗄️ DB connection strings, SMTP credentials, OAuth secrets
- 📂 Exposed `.env`, `.git`, `wp-config.php`, backup files
- 🛠️ Admin panels, debug endpoints, Spring Actuator
- 📧 **Email harvesting** from all crawled pages

</td>
</tr>
<tr>
<td width="50%">

### 📁 File Intelligence

- 📥 **Auto-downloads** all discovered files (200MB limit)
- 🗜️ Handles: PDF, ZIP, SQL, config, code, media files
- 🔍 **Scans text files** for embedded secrets post-download
- 📂 Organized output by domain in `files/` subdirectory

</td>
<td width="50%">

### 📊 Reporting & UI

- 🖥️ **Live Rich TUI dashboard** with real-time stats
- 📈 Requests/sec, depth tracking, active worker count
- 📝 **Detailed TXT report** — grouped by severity + category
- 🗂️ **Structured JSON export** — machine-readable results
- 🎨 Color-coded severity indicators

</td>
</tr>
</table>

---

## 🎯 Intel Categories

| Category | Severity | Examples |
|---|---|---|
| **AWS** | 🔴 CRITICAL | Access Key ID, Secret Key, Session Token |
| **Private Keys** | 🔴 CRITICAL | RSA/EC/DSA/PGP private keys |
| **Tokens** | 🔴 CRITICAL | JWT, GitHub PAT, OpenAI key, Stripe live key |
| **SMTP** | 🔴 CRITICAL | SMTP credentials, SendGrid API key |
| **Database** | 🔴 CRITICAL | Connection strings, DB passwords |
| **Credentials** | 🔴 CRITICAL | Hardcoded passwords, admin credentials |
| **Exposed Files** | 🔴 CRITICAL | `.env`, `.git`, `wp-config.php`, `.svn` |
| **Google Cloud** | 🟠 HIGH | GCP API keys, GCS buckets |
| **Firebase** | 🟠 HIGH | Firebase DB URLs, API keys |
| **API Endpoints** | 🟠 HIGH | Admin/internal/GraphQL endpoints |
| **Cloud Misconfig** | 🟠 HIGH | Azure Blob, DigitalOcean Spaces, S3 ACL |
| **Admin/Login** | 🟠 HIGH | Admin panels, login endpoints, 2FA |
| **Debug/Dev** | 🟠 HIGH | Spring Actuator, dev consoles, status pages |
| **Misc Secrets** | 🟠 HIGH | Slack webhooks, Discord tokens, OAuth secrets |
| **Directory Listing** | 🟠 HIGH | Open directory indexes |

---

## 📦 Installation

### Prerequisites

- Python **3.8+**
- pip

### Quick Setup

```bash
# 1. Clone the repository
git clone https://github.com/C4N2yFl0SS/cyfrin-crawler.git
cd cyfrin-crawler

# 2. (Recommended) Create a virtual environment
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run
python3 cyfrin.py
```

### Dependencies

| Package | Purpose |
|---|---|
| `aiohttp` | Async HTTP client engine |
| `aiofiles` | Async file I/O for downloads |
| `beautifulsoup4` | HTML parsing & link extraction |
| `lxml` | Fast HTML/XML parser (optional but recommended) |
| `rich` | Live TUI dashboard & colored output |

---

## 🚀 Usage

```bash
python3 cyfrin.py
```

You will be prompted for a single input:

```
  ► Enter Domain Name (e.g. example.com) :
```

Enter your target domain — no flags, no config files. CYFRIN CRAWLER handles everything automatically.

### Example Session

```
  ► Enter Domain Name (e.g. example.com) : target.com

  ► Target        : https://target.com
  ► Output Folder : target/
  ► Mode          : UNLIMITED depth · AUTO-STOP · Robots OFF · All subdomains

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ Launching ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

The **live dashboard** shows real-time progress:

```
╭──────────────────── 🕷 CYFRIN CRAWLER v2.0 → target.com ──────────────────────╮
│ ⏱  Elapsed          00:02:14  │  ⚡ Recent URLs                              │
│ 📄 Pages Crawled    1,247     │  200  https://target.com/api/v1/users         │
│ ❌ Failed           23        │  403  https://target.com/admin                │
│ 📁 Files Downloaded 89        │  200  https://target.com/.env                 │
│ 💾 Data             12.4 MB   │  ...                                          │
│ 🌐 URLs Visited     1,412     │  🚨 Findings                                  │
│ 📊 Depth Reached    7         │  CRITICAL [Exposed Files] Exposed .env File   │
│ 🔁 Req/Sec          8.3       │  HIGH [Admin/Login] Admin Panel               │
│ 🕷  Workers         50         │  CRITICAL [Credentials] Hardcoded Password    │
│ ─────────────────────────      │  ...                                          │
│ 🔴 CRITICAL         3         │                                                │
│ 🟠 HIGH             11        │                                                │
│ 🔎 Total Findings  14         │                                                │
╰────────────────────────────────────────────────────────────────────────────────╯
```

---

## 📂 Output Structure

```
target/
├── sensitive_findings.txt      # Full human-readable report, grouped by severity
├── results.json                # Machine-readable JSON export
└── files/
    └── target.com/
        ├── backup.sql          # Downloaded files, organized by domain
        ├── config.php
        ├── export.zip
        └── ...
```

### `sensitive_findings.txt` Format

```
════════════════════════════════════════════════════════════════════════════════
  CYFRIN CRAWLER v2.0 — SENSITIVE FINDINGS REPORT
  Target  : https://target.com
  Date    : 2024-11-15 14:32:07
  Total   : 14  (CRITICAL: 3  HIGH: 11)
════════════════════════════════════════════════════════════════════════════════

────────────────────────────────────────────────────────────────────────────────
  [CRITICAL]  (3 findings)
────────────────────────────────────────────────────────────────────────────────

  ▶  EXPOSED FILES  (1)

  [001]  Exposed .env File
         URL     : https://target.com/.env
         Match   : /.env
         Context : ... DB_PASSWORD=supersecret123 AWS_SECRET_KEY=AKIAIOSFOD ...
```

### `results.json` Format

```json
{
  "meta": {
    "crawl_date": "2024-11-15T14:32:07",
    "target": "https://target.com",
    "stats": {
      "pages_crawled": 1247,
      "files_downloaded": 89,
      "bytes_downloaded": 12996608,
      "emails_found": 23,
      "findings_total": 14,
      "findings_critical": 3,
      "findings_high": 11,
      "depth_reached": 7,
      "elapsed": "00:02:14"
    }
  },
  "findings": [...],
  "emails": [...]
}
```

---

## ⚙️ Configuration

CYFRIN CRAWLER ships with sensible defaults. Core constants can be tweaked inside the `CyfrinCrawler` class:

| Constant | Default | Description |
|---|---|---|
| `CONCURRENCY` | `50` | Parallel async workers |
| `TIMEOUT` | `25s` | Per-request timeout |
| `RETRIES` | `3` | Retry attempts per URL |
| `MAX_FILE_MB` | `200` | Max file download size |

---

## 🏗️ Architecture

```
cyfrin.py
│
├── IntelEngine          ← 400+ regex patterns, false-positive filtering
├── BloomFilter          ← Probabilistic deduplication (5M capacity)
├── CyfrinCrawler           ← Core async crawler
│   ├── _fetch()         ← HTTP client with retry/backoff
│   ├── _crawl()         ← Page fetch → intel scan → link extraction
│   ├── _dl_file()       ← File download → secret scan
│   ├── _worker()        ← Priority queue consumer
│   ├── _write_report()  ← TXT report generator
│   └── _export_json()   ← JSON export
├── Dashboard            ← Rich live TUI
└── Stats                ← Real-time metrics tracker
```

---

## 🛡️ Ethical Use & Legal

This tool is provided **strictly for**:

- ✅ Authorized penetration testing engagements
- ✅ Bug bounty programs with explicit scope
- ✅ Security research on systems you own
- ✅ CTF (Capture The Flag) competitions
- ✅ Educational / learning purposes in lab environments

**This tool is NOT for:**

- ❌ Unauthorized access to systems
- ❌ Scanning targets without written permission
- ❌ Any illegal activity

**By using CYFRIN CRAWLER, you agree that you have all necessary authorizations and accept full legal and ethical responsibility for your actions.**

---

## 👤 Author

<div align="center">

**Jannatul Islam**

[![GitHub](https://img.shields.io/badge/GitHub-C4N2yFl0SS-181717?style=for-the-badge&logo=github)](https://github.com/C4N2yFl0SS)

</div>

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

```
 ________      ___    ___ ________ ________  ___  ________      
|\   ____\    |\  \  /  /|\  _____\\   __  \|\  \|\   ___  \    
\ \  \___|    \ \  \/  / | \  \__/\ \  \|\  \ \  \ \  \\ \  \   
 \ \  \        \ \    / / \ \   __\\ \   _  _\ \  \ \  \\ \  \  
  \ \  \____    \/   / /   \ \  \_| \ \  \\  \\ \  \ \  \\ \  \ 
   \ \_______\__/   / /     \ \__\   \ \__\\ _\\ \__\ \__\\ \__\
    \|_______|\____/ /       \|__|    \|__|\|__|\|__|\|__| \|__|
             \|____|/                                           
                                                                                                
```

*Hunt responsibly. Hack ethically.*

</div>
