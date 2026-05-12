#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                      CYFRIN CRAWLER v2.0                               ║
║        Unlimited Depth · Auto-Stop · Sensitive Intel Engine                ║
║                                                                             ║
║  Author : Jannatul Islam                                                    ║
║  GitHub : https://github.com/C4N2yFl0SS                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import aiohttp
import aiofiles
import hashlib
import json
import math
import mimetypes
import os
import re
import signal
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

# ── Optional deps ─────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich import box
    RICH = True
except ImportError:
    RICH = False

try:
    from bs4 import BeautifulSoup
    BS4 = True
except ImportError:
    BS4 = False

try:
    import lxml  # noqa
    LXML = True
except ImportError:
    LXML = False

# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────

BANNER = r"""
 ________      ___    ___ ________ ________  ___  ________      
|\   ____\    |\  \  /  /|\  _____\\   __  \|\  \|\   ___  \    
\ \  \___|    \ \  \/  / | \  \__/\ \  \|\  \ \  \ \  \\ \  \   
 \ \  \        \ \    / / \ \   __\\ \   _  _\ \  \ \  \\ \  \  
  \ \  \____    \/   / /   \ \  \_| \ \  \\  \\ \  \ \  \\ \  \ 
   \ \_______\__/   / /     \ \__\   \ \__\\ _\\ \__\ \__\\ \__\
    \|_______|\____/ /       \|__|    \|__|\|__|\|__|\|__| \|__|
             \|____|/                                           
                                                                                              
"""
TAGLINE = "        CYFRIN CRAWLER v2.0  |  Unlimited Depth · Auto-Stop · Sensitive Intel Engine"

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

UNLIMITED = 999_999_999

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Version/17.4 Mobile/15E148 Safari/604.1",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]

FILE_EXTENSIONS = [
    # documents
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".odt", ".ods", ".odp", ".txt", ".rtf", ".csv", ".epub",
    # images
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp", ".ico", ".tiff",
    # audio / video
    ".mp3", ".wav", ".ogg", ".flac", ".aac", ".m4a",
    ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm",
    # archives
    ".zip", ".tar", ".gz", ".bz2", ".rar", ".7z", ".xz", ".tgz",
    # code / data
    ".py", ".js", ".ts", ".php", ".rb", ".go", ".java", ".sh", ".sql",
    ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".bak", ".backup", ".old", ".swp", ".dump",
    # executables
    ".exe", ".msi", ".dmg", ".deb", ".rpm", ".apk",
]

# ─────────────────────────────────────────────────────────────────────────────
# SENSITIVE INTEL PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

# (category, severity, label, regex_pattern)
INTEL_PATTERNS: List[Tuple[str, str, str, str]] = [

    # ── AWS ──────────────────────────────────────────────────────────────────
    ("AWS", "CRITICAL", "AWS Access Key ID",
     r'AKIA[0-9A-Z]{16}'),
    ("AWS", "CRITICAL", "AWS Secret Access Key",
     r'(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key[\s]*[=:][^\s\'"<>&]{20,}'),
    ("AWS", "CRITICAL", "AWS Session Token",
     r'(?i)x-amz-security-token[\s]*[=:][^\s\'"<>&]{40,}'),
    ("AWS", "HIGH",     "AWS S3 Bucket URL",
     r'[a-z0-9\-]+\.s3[.\-][a-z0-9\-]*\.amazonaws\.com'),
    ("AWS", "HIGH",     "AWS Account ID",
     r'(?i)aws[_\-]?account[_\-]?id[\s]*[=:]\s*\d{12}'),

    # ── Google Cloud ──────────────────────────────────────────────────────────
    ("Google Cloud", "CRITICAL", "Google API Key",
     r'AIza[0-9A-Za-z\-_]{35}'),
    ("Google Cloud", "HIGH",     "GCS Bucket URL",
     r'storage\.googleapis\.com/[^\s\'"<>]+'),

    # ── Private Keys ──────────────────────────────────────────────────────────
    ("Private Keys", "CRITICAL", "RSA/EC/DSA Private Key",
     r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
    ("Private Keys", "CRITICAL", "PGP Private Key",
     r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
    ("Private Keys", "MEDIUM",   "SSL Certificate",
     r'-----BEGIN CERTIFICATE-----'),

    # ── Tokens / Auth ─────────────────────────────────────────────────────────
    ("Tokens", "CRITICAL", "JWT Token",
     r'eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}'),
    ("Tokens", "CRITICAL", "GitHub Personal Access Token",
     r'ghp_[A-Za-z0-9]{36}'),
    ("Tokens", "CRITICAL", "GitHub Fine-Grained PAT",
     r'github_pat_[A-Za-z0-9_]{82}'),
    ("Tokens", "CRITICAL", "OpenAI API Key",
     r'sk-[A-Za-z0-9]{48}'),
    ("Tokens", "CRITICAL", "Stripe Live Secret Key",
     r'sk_live_[A-Za-z0-9]{24,}'),
    ("Tokens", "HIGH",     "Generic API Key/Token",
     r'(?i)(api[_\-]?key|apikey|api[_\-]?token)[_\-\s]*[=:][^\s\'"<>&]{16,}'),
    ("Tokens", "HIGH",     "Access Token",
     r'(?i)access[_\-]?token[\s]*[=:][^\s\'"<>&]{20,}'),
    ("Tokens", "HIGH",     "Auth Token",
     r'(?i)auth[_\-]?token[\s]*[=:][^\s\'"<>&]{16,}'),
    ("Tokens", "HIGH",     "Secret Key",
     r'(?i)secret[_\-]?key[\s]*[=:][^\s\'"<>&]{16,}'),
    ("Tokens", "HIGH",     "Twilio Account SID",
     r'AC[a-z0-9]{32}'),

    # ── SMTP / Mail ───────────────────────────────────────────────────────────
    ("SMTP", "CRITICAL", "SMTP Credentials",
     r'(?i)smtp[_\-]?(host|server|url|pass|password|user|username|port)[\s]*[=:][^\s\'"<>&]+'),
    ("SMTP", "CRITICAL", "SendGrid API Key",
     r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}'),
    ("SMTP", "HIGH",     "Mail Service API Key",
     r'(?i)(mailgun|mailchimp|mailjet)[_\-]?api[_\-]?key[\s]*[=:][^\s\'"<>&]{16,}'),
    ("SMTP", "HIGH",     "SMTP Connection String",
     r'(?i)smtp[s]?://[^\s\'"<>]+'),

    # ── Database ──────────────────────────────────────────────────────────────
    ("Database", "CRITICAL", "Database Connection String",
     r'(?i)(mysql|postgres|postgresql|mongodb|redis|mssql|oracle|mariadb|sqlite)://[^\s\'"<>]+'),
    ("Database", "CRITICAL", "Database Password",
     r'(?i)db[_\-]?(pass|password|pwd)[\s]*[=:][^\s\'"<>&]{4,}'),
    ("Database", "HIGH",     "Database Config",
     r'(?i)db[_\-]?(user|username|host|name)[\s]*[=:][^\s\'"<>&]+'),
    ("Database", "HIGH",     "Connection String",
     r'(?i)connection[_\-]?string[\s]*[=:][^\s\'"<>]+'),

    # ── Credentials ───────────────────────────────────────────────────────────
    ("Credentials", "CRITICAL", "Hardcoded Password",
     r'(?i)(password|passwd|pwd|pass)[\s]*[=:][^\s\'"<>&]{4,}'),
    ("Credentials", "CRITICAL", "Admin Credential",
     r'(?i)admin[_\-]?(pass|password|pwd|secret)[\s]*[=:][^\s\'"<>&]{4,}'),
    ("Credentials", "HIGH",     "Default Credential",
     r'(?i)default[_\-]?(pass|password|admin)[^\s\'"<>&]*'),
    ("Credentials", "HIGH",     "Hardcoded Username",
     r'(?i)(username|user|login)[\s]*[=:][^\s\'"<>&]+'),

    # ── Cloud Misconfig ───────────────────────────────────────────────────────
    ("Cloud Misconfig", "HIGH", "Azure Blob Storage",
     r'[a-z0-9\-]+\.blob\.core\.windows\.net'),
    ("Cloud Misconfig", "HIGH", "DigitalOcean Spaces",
     r'[a-z0-9\-]+\.digitaloceanspaces\.com'),
    ("Cloud Misconfig", "HIGH", "S3 Public ACL",
     r'(?i)x-amz-acl:\s*public-read'),

    # ── Firebase ──────────────────────────────────────────────────────────────
    ("Firebase", "HIGH", "Firebase Database URL",
     r'[a-z0-9\-]+\.firebaseio\.com'),
    ("Firebase", "HIGH", "Firebase API Key",
     r'(?i)firebase[_\-]?api[_\-]?key[\s]*[=:][^\s\'"<>&]{30,}'),

    # ── Exposed Sensitive Files / Endpoints ───────────────────────────────────
    ("Exposed Files", "CRITICAL", "Exposed .env File",
     r'(?i)(^|/)\.env(\b|$)'),
    ("Exposed Files", "CRITICAL", "WordPress Config Exposed",
     r'(?i)/wp-config\.php'),
    ("Exposed Files", "CRITICAL", "Exposed .git Directory",
     r'(?i)(^|/)\.git(/|$)'),
    ("Exposed Files", "CRITICAL", "Exposed .svn Directory",
     r'(?i)(^|/)\.svn(/|$)'),
    ("Exposed Files", "HIGH",     "Config File Exposed",
     r'(?i)/config\.(php|py|js|json|yml|yaml|xml|ini)(\?|$)'),
    ("Exposed Files", "HIGH",     "Backup File",
     r'(?i)\.(bak|backup|old|orig|copy|save|swp|sql|dump)(\?|$)'),
    ("Exposed Files", "HIGH",     "PHP Info Page",
     r'(?i)/phpinfo(\.php)?(\?|$)'),
    ("Exposed Files", "HIGH",     "Exposed .DS_Store",
     r'(?i)/\.DS_Store(\?|$)'),

    # ── API Endpoints ─────────────────────────────────────────────────────────
    ("API Endpoints", "HIGH",   "Sensitive API Endpoint",
     r'(?i)/api/v?\d*/(admin|users|accounts|keys|tokens|secrets|config|credentials)'),
    ("API Endpoints", "HIGH",   "Internal/Private API",
     r'(?i)/api/(internal|private|debug|test|dev|staging)'),
    ("API Endpoints", "HIGH",   "GraphQL Endpoint",
     r'(?i)/graphql(\?|$|/)'),
    ("API Endpoints", "MEDIUM", "API Documentation",
     r'(?i)/(swagger|api-docs|openapi)(\.json|\.yaml|/)?(\?|$)'),

    # ── Admin / Login Panels ──────────────────────────────────────────────────
    ("Admin/Login", "HIGH",   "Admin Panel",
     r'(?i)/(admin|administrator|wp-admin|dashboard|manage|management|portal|panel|control)(/?$|/|\?)'),
    ("Admin/Login", "MEDIUM", "Login Endpoint",
     r'(?i)/(login|signin|sign-in|auth|authenticate|sso|oauth)(/?$|/|\?)'),
    ("Admin/Login", "MEDIUM", "Database Admin Panel",
     r'(?i)/(adminer|phpmyadmin|pma)(\.php)?(\?|$)'),
    ("Admin/Login", "MEDIUM", "Password Reset",
     r'(?i)/(forgot.?pass|reset.?pass|password.?reset)(/?$|/|\?)'),
    ("Admin/Login", "MEDIUM", "2FA Endpoint",
     r'(?i)/(2fa|mfa|totp|otp|two.?factor)(/?$|/|\?)'),

    # ── Debug / Dev Endpoints ─────────────────────────────────────────────────
    ("Debug/Dev", "HIGH",   "Spring Actuator Sensitive",
     r'(?i)/actuator/(env|heapdump|threaddump|dump|trace|beans|mappings)'),
    ("Debug/Dev", "HIGH",   "Server Status Page",
     r'(?i)/(server-status|server-info)(\?|$)'),
    ("Debug/Dev", "HIGH",   "Dev Console",
     r'(?i)/(console|h2-console|druid)(/?$|/|\?)'),
    ("Debug/Dev", "MEDIUM", "Debug/Test Endpoint",
     r'(?i)/(debug|test|dev|staging|uat|qa|sandbox)(/?$|/|\?)'),
    ("Debug/Dev", "MEDIUM", "Spring Actuator",
     r'(?i)/actuator(/?$|/)'),
    ("Debug/Dev", "MEDIUM", "Metrics/Health/Trace",
     r'(?i)/(metrics|trace|health|status)(\?|$)'),

    # ── Misc Secrets ──────────────────────────────────────────────────────────
    ("Misc Secrets", "HIGH", "Slack Webhook URL",
     r'https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+'),
    ("Misc Secrets", "HIGH", "Slack Token",
     r'(?i)slack[_\-]?(token|webhook|api[_\-]?key)[\s]*[=:][^\s\'"<>&]{20,}'),
    ("Misc Secrets", "HIGH", "Discord Token/Webhook",
     r'(?i)discord[_\-]?(token|webhook)[\s]*[=:][^\s\'"<>&]{20,}'),
    ("Misc Secrets", "HIGH", "Heroku API Key",
     r'(?i)heroku[_\-]?api[_\-]?key[\s]*[=:][^\s\'"<>&]{30,}'),
    ("Misc Secrets", "HIGH", "OAuth Client Secret",
     r'(?i)client[_\-]?secret[\s]*[=:][^\s\'"<>&]{12,}'),
    ("Misc Secrets", "HIGH", "App Secret/Key",
     r'(?i)app[_\-]?(secret|key|token)[\s]*[=:][^\s\'"<>&]{16,}'),
    ("Misc Secrets", "HIGH", "Encryption Key",
     r'(?i)encryption[_\-]?key[\s]*[=:][^\s\'"<>&]{16,}'),
    ("Misc Secrets", "HIGH", "Master Key/Secret",
     r'(?i)master[_\-]?(key|secret|password)[\s]*[=:][^\s\'"<>&]{8,}'),
    ("Misc Secrets", "HIGH", "Private Key (generic)",
     r'(?i)private[_\-]?key[\s]*[=:][^\s\'"<>&]{20,}'),

    # ── Directory Listing ─────────────────────────────────────────────────────
    ("Directory Listing", "HIGH", "Directory Listing Enabled",
     r'(?i)(Index of /|<title>Directory listing for|\[To Parent Directory\])'),

    # ── Backup / Dev Paths ────────────────────────────────────────────────────
    ("Backup/Dev Paths", "HIGH", "Backup Directory",
     r'(?i)/backup[s]?(/|\.|$)'),
    ("Backup/Dev Paths", "HIGH", "Logs Directory",
     r'(?i)/logs?(/|\.|$)'),
    ("Backup/Dev Paths", "HIGH", "Upload Directory",
     r'(?i)/(upload[s]?|file[s]?)(/|\.|$)'),
]

# ─────────────────────────────────────────────────────────────────────────────
# FINDING DATACLASS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    category:     str
    severity:     str
    label:        str
    url:          str
    match:        str
    context:      str


# ─────────────────────────────────────────────────────────────────────────────
# SENSITIVE INTEL ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class IntelEngine:
    def __init__(self):
        self._rules: List[Tuple[str, str, str, re.Pattern]] = []
        for category, severity, label, pattern in INTEL_PATTERNS:
            try:
                self._rules.append((category, severity, label,
                                    re.compile(pattern, re.IGNORECASE | re.MULTILINE)))
            except re.error:
                pass

        self._fp = [
            re.compile(r'^(true|false|null|undefined|none|0|1)$', re.I),
            re.compile(r'^[a-zA-Z]{1,3}$'),
            re.compile(r'^(http|https|ftp)$', re.I),
        ]

    def scan(self, url: str, text: str) -> List[Finding]:
        findings: List[Finding] = []
        seen: Set[str] = set()
        full = f"URL: {url}\n\n{text}"

        for category, severity, label, regex in self._rules:
            for m in regex.finditer(full):
                match_str = m.group(0).strip()
                key = f"{label}:{match_str[:60]}"
                if key in seen:
                    continue
                if any(fp.match(match_str) for fp in self._fp):
                    continue
                seen.add(key)

                s = max(0, m.start() - 120)
                e = min(len(full), m.end() + 120)
                ctx = full[s:e].replace("\n", " ").strip()

                findings.append(Finding(
                    category=category,
                    severity=severity,
                    label=label,
                    url=url,
                    match=match_str,
                    context=ctx,
                ))
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# BLOOM FILTER
# ─────────────────────────────────────────────────────────────────────────────

class BloomFilter:
    def __init__(self, capacity: int = 5_000_000, error_rate: float = 0.001):
        self.size = int(-capacity * math.log(error_rate) / (math.log(2) ** 2))
        self.hashes = max(1, int(self.size / capacity * math.log(2)))
        self.bits = bytearray(self.size // 8 + 1)

    def _positions(self, item: str) -> List[int]:
        data = item.encode()
        return [
            int(hashlib.md5(data + i.to_bytes(2, "big")).hexdigest(), 16) % self.size
            for i in range(self.hashes)
        ]

    def add(self, item: str):
        for p in self._positions(item):
            self.bits[p // 8] |= 1 << (p % 8)

    def __contains__(self, item: str) -> bool:
        return all(self.bits[p // 8] & (1 << (p % 8)) for p in self._positions(item))


# ─────────────────────────────────────────────────────────────────────────────
# STATS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Stats:
    start_time:       float = field(default_factory=time.time)
    pages_crawled:    int   = 0
    pages_failed:     int   = 0
    files_found:      int   = 0
    files_downloaded: int   = 0
    bytes_downloaded: int   = 0
    urls_queued:      int   = 0
    urls_visited:     int   = 0
    depth_reached:    int   = 0
    active_workers:   int   = 0
    findings_total:   int   = 0
    findings_critical:int   = 0
    findings_high:    int   = 0
    rps:              float = 0.0
    _rps_count:       int   = 0
    _rps_time:        float = field(default_factory=time.time)

    def tick_rps(self):
        now = time.time()
        dt = now - self._rps_time
        if dt >= 1.0:
            total = self.pages_crawled + self.pages_failed
            self.rps = (total - self._rps_count) / dt
            self._rps_count = total
            self._rps_time = now

    @property
    def elapsed(self) -> str:
        s = int(time.time() - self.start_time)
        h, r = divmod(s, 3600); m, s = divmod(r, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    @property
    def bytes_human(self) -> str:
        b = self.bytes_downloaded
        for u in ["B", "KB", "MB", "GB"]:
            if b < 1024: return f"{b:.1f} {u}"
            b //= 1024
        return f"{b:.1f} TB"


# ─────────────────────────────────────────────────────────────────────────────
# URL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def normalize(url: str) -> str:
    try:
        p = urlparse(url.strip())
        path = p.path or "/"
        while "//" in path: path = path.replace("//", "/")
        if path != "/" and path.endswith("/"): path = path.rstrip("/")
        return urlunparse((p.scheme.lower(), p.netloc.lower(), path, "", p.query, ""))
    except Exception:
        return url

def domain_of(url: str) -> str:
    return urlparse(url).netloc.lower()

def base_domain(url: str) -> str:
    parts = domain_of(url).split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else parts[0]

def in_scope(url: str, seed_domain: str) -> bool:
    """True if url belongs to same base domain (covers all subdomains)."""
    bd = base_domain(url)
    return bd == seed_domain or url.startswith(("http://", "https://"))  and bd == seed_domain

def is_file(url: str) -> bool:
    path = urlparse(url).path.lower().split("?")[0]
    return any(path.endswith(ext) for ext in FILE_EXTENSIONS)

def chash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def main_name(raw: str) -> str:
    """Extract folder-safe main name from domain. e.g. www.infra.edu.bd → infra"""
    d = re.sub(r'^https?://', '', raw).strip().rstrip("/").split(":")[0]
    d = re.sub(r'^www\.', '', d)
    parts = d.split(".")
    MULTI = {"co", "com", "net", "org", "gov", "edu", "ac", "or"}
    if len(parts) >= 3 and parts[-2] in MULTI:
        return ".".join(parts[:-2])
    if len(parts) >= 2:
        return ".".join(parts[:-1])
    return parts[0]


# ─────────────────────────────────────────────────────────────────────────────
# LINK EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────

_JS_URL  = re.compile(r'''(?:href|src|action|url|endpoint|api|path)\s*[=:]\s*['"`]([^'"`\s]{4,})['"`]''', re.I)
_CSS_URL = re.compile(r'url\([\'"]?([^\'")\s]{4,})[\'"]?\)', re.I)
_LOC_URL = re.compile(r'<loc>(.*?)</loc>', re.I | re.S)
_EMAIL   = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')

def extract_links(html: str, base: str) -> Tuple[List[str], List[str]]:
    urls: Set[str] = set()
    emails: Set[str] = set()

    if BS4:
        try:
            parser = "lxml" if LXML else "html.parser"
            soup = BeautifulSoup(html, parser)
            for t in soup.find_all(["a", "link", "area"], href=True):
                urls.add(t["href"])
            for t in soup.find_all(["img", "script", "iframe", "embed", "source"], src=True):
                urls.add(t["src"])
            for t in soup.find_all("form", action=True):
                urls.add(t["action"])
            for t in soup.find_all(True):
                for attr, val in t.attrs.items():
                    if attr.startswith("data-") and isinstance(val, str) and (val.startswith("/") or val.startswith("http")):
                        urls.add(val)
            for t in soup.find_all("meta", content=True):
                c = t.get("content", "")
                if c.startswith(("http", "/")):
                    urls.add(c)
            for s in soup.find_all("script"):
                if s.string:
                    for m in _JS_URL.finditer(s.string): urls.add(m.group(1))
            for s in soup.find_all("style"):
                if s.string:
                    for m in _CSS_URL.finditer(s.string): urls.add(m.group(1))
            emails.update(_EMAIL.findall(html))
        except Exception:
            pass
    else:
        for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.I): urls.add(m.group(1))
        for m in re.finditer(r'src=["\']([^"\']+)["\']',  html, re.I): urls.add(m.group(1))
        emails.update(_EMAIL.findall(html))

    # Sitemaps
    for m in _LOC_URL.finditer(html): urls.add(m.group(1).strip())

    resolved = []
    for u in urls:
        try:
            u = u.strip()
            if not u or u.startswith(("javascript:", "mailto:", "tel:", "data:", "#", "void")):
                continue
            full = urljoin(base, u)
            p = urlparse(full)
            if p.scheme in ("http", "https"):
                resolved.append(full)
        except Exception:
            pass

    return resolved, list(emails)


# ─────────────────────────────────────────────────────────────────────────────
# LIVE DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────

class Dashboard:
    def __init__(self, target: str, outdir: str):
        self.target = target
        self.outdir = outdir
        self.console = Console() if RICH else None
        self._live = None
        self._urls: deque = deque(maxlen=12)
        self._finds: deque = deque(maxlen=8)

    def add_url(self, url: str, status: int):
        col = "green" if status < 400 else "red"
        self._urls.appendleft(f"[{col}]{status}[/]  {url[:90]}")

    def add_finding(self, f: Finding):
        col = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow"}.get(f.severity, "white")
        self._finds.appendleft(f"[{col}]{f.severity}[/] [{f.category}] {f.label}")

    def render(self, s: Stats) -> Panel:
        s.tick_rps()
        grid = Table.grid(expand=True)
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)

        left = Table(box=box.SIMPLE, show_header=False, expand=True)
        left.add_column("k", style="bold cyan",    min_width=22)
        left.add_column("v", style="bright_white", min_width=12)
        left.add_row("⏱  Elapsed",          s.elapsed)
        left.add_row("📄 Pages Crawled",     f"[green]{s.pages_crawled}[/]")
        left.add_row("❌ Failed",            f"[red]{s.pages_failed}[/]")
        left.add_row("📁 Files Downloaded",  f"[green]{s.files_downloaded}[/]  found: {s.files_found}")
        left.add_row("💾 Data",              f"[magenta]{s.bytes_human}[/]")
        left.add_row("🌐 URLs Visited",      f"[white]{s.urls_visited}[/]  queued: {s.urls_queued}")
        left.add_row("📊 Depth Reached",     f"[white]{s.depth_reached}[/]")
        left.add_row("🔁 Req/Sec",           f"[yellow]{s.rps:.1f}[/]")
        left.add_row("🕷  Workers",           f"[cyan]{s.active_workers}[/]")
        left.add_row("", "")
        crit_col = "bold red"   if s.findings_critical > 0 else "dim"
        high_col = "red"        if s.findings_high > 0      else "dim"
        left.add_row("🔴 CRITICAL",          f"[{crit_col}]{s.findings_critical}[/]")
        left.add_row("🟠 HIGH",              f"[{high_col}]{s.findings_high}[/]")
        left.add_row("🔎 Total Findings",    f"[bright_white]{s.findings_total}[/]")

        right = Table(box=box.SIMPLE, show_header=True, expand=True)
        right.add_column("⚡ Recent URLs",  style="dim")
        for u in self._urls: right.add_row(u)
        right.add_row("")
        right.add_column("🚨 Findings", style="dim")
        for f in self._finds: right.add_row(f)

        grid.add_row(left, right)
        return Panel(
            grid,
            title=f"[bold red]🕷 CYFRIN CRAWLER v2.0[/bold red]  [dim]→[/dim]  [cyan]{self.target}[/cyan]",
            border_style="bright_red",
            subtitle=f"[dim]output: {self.outdir}/[/dim]",
        )


# ─────────────────────────────────────────────────────────────────────────────
# CORE CRAWLER
# ─────────────────────────────────────────────────────────────────────────────

class CyfrinCrawler:
    CONCURRENCY = 50
    TIMEOUT     = 25
    RETRIES     = 3
    MAX_FILE_MB = 200

    def __init__(self, target_url: str, output_dir: str):
        self.target     = target_url
        self.outdir     = output_dir
        self.seed_base  = base_domain(target_url)
        self.stats      = Stats()
        self.bloom      = BloomFilter()
        self.intel      = IntelEngine()
        self.dash       = Dashboard(target_url, output_dir)

        self._queue:     asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._session:   Optional[aiohttp.ClientSession] = None
        self._shutdown:  bool = False
        self._ua_idx:    int  = 0
        self._findings:  List[Finding] = []
        self._find_lock: asyncio.Lock = asyncio.Lock()
        self._visited:   Set[str] = set()   # in-memory, no DB
        self._emails:    Set[str] = set()
        self._content_hashes: Set[str] = set()

        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, "files"), exist_ok=True)

    # ── UA rotation ──────────────────────────────────────────────────────────
    def _ua(self) -> str:
        ua = USER_AGENTS[self._ua_idx % len(USER_AGENTS)]
        self._ua_idx += 1
        return ua

    def _hdrs(self) -> Dict[str, str]:
        return {
            "User-Agent":                self._ua(),
            "Accept":                    "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language":           "en-US,en;q=0.9",
            "Accept-Encoding":           "gzip, deflate, br",
            "Connection":                "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

    # ── Session ───────────────────────────────────────────────────────────────
    async def _make_session(self) -> aiohttp.ClientSession:
        conn = aiohttp.TCPConnector(
            limit=self.CONCURRENCY * 2,
            limit_per_host=15,
            ttl_dns_cache=300,
            ssl=False,
            enable_cleanup_closed=True,
        )
        to = aiohttp.ClientTimeout(
            total=self.TIMEOUT,
            connect=8,
            sock_connect=8,
            sock_read=self.TIMEOUT,
        )
        return aiohttp.ClientSession(connector=conn, timeout=to, trust_env=True)

    # ── Fetch ─────────────────────────────────────────────────────────────────
    async def _fetch(self, url: str) -> Tuple[Optional[bytes], int, Dict]:
        for attempt in range(self.RETRIES + 1):
            try:
                async with self._session.get(
                    url, headers=self._hdrs(),
                    allow_redirects=True, max_redirects=10,
                ) as r:
                    data = await r.read()
                    return data, r.status, dict(r.headers)
            except asyncio.TimeoutError:
                if attempt < self.RETRIES:
                    await asyncio.sleep(1.5 * (1.5 ** attempt))
            except aiohttp.ClientError:
                if attempt < self.RETRIES:
                    await asyncio.sleep(1.5 * (1.5 ** attempt))
            except Exception:
                break
        return None, 0, {}

    # ── Save finding ──────────────────────────────────────────────────────────
    async def _add_finding(self, f: Finding):
        async with self._find_lock:
            self._findings.append(f)
            self.stats.findings_total += 1
            if f.severity == "CRITICAL": self.stats.findings_critical += 1
            elif f.severity == "HIGH":   self.stats.findings_high     += 1
            self.dash.add_finding(f)

    # ── Download file ─────────────────────────────────────────────────────────
    async def _dl_file(self, url: str):
        try:
            data, status, hdrs = await self._fetch(url)
            if not data or status not in range(200, 300): return
            if len(data) > self.MAX_FILE_MB * 1024 * 1024: return

            h = chash(data)
            if h in self._content_hashes: return
            self._content_hashes.add(h)

            p = urlparse(url)
            fname = os.path.basename(p.path) or f"file_{h[:8]}"
            fname = re.sub(r'[<>:"/\\|?*]', '_', fname)
            if "." not in fname:
                mime = hdrs.get("Content-Type", "").split(";")[0].strip()
                fname += mimetypes.guess_extension(mime) or ""

            ddir = os.path.join(self.outdir, "files", domain_of(url))
            os.makedirs(ddir, exist_ok=True)
            fpath = os.path.join(ddir, fname)
            if os.path.exists(fpath):
                base, ext = os.path.splitext(fname)
                fpath = os.path.join(ddir, f"{base}_{h[:6]}{ext}")

            async with aiofiles.open(fpath, "wb") as f:
                await f.write(data)

            self.stats.files_downloaded += 1
            self.stats.bytes_downloaded += len(data)

            # Scan text-based files for secrets
            text_exts = {".js", ".json", ".xml", ".txt", ".env", ".yml", ".yaml",
                         ".cfg", ".conf", ".ini", ".php", ".py", ".sh", ".sql", ".log", ".bak"}
            if any(url.lower().split("?")[0].endswith(e) for e in text_exts):
                try:
                    txt = data.decode("utf-8", errors="replace")
                    for f_obj in self.intel.scan(url, txt):
                        await self._add_finding(f_obj)
                except Exception:
                    pass
        except Exception:
            pass

    # ── Crawl single page ─────────────────────────────────────────────────────
    async def _crawl(self, url: str, depth: int):
        self.stats.active_workers += 1
        try:
            norm = normalize(url)
            data, status, hdrs = await self._fetch(url)

            self.stats.urls_visited += 1
            self.dash.add_url(url, status or 0)

            if data is None:
                self.stats.pages_failed += 1
                return

            # Mark visited
            self._visited.add(norm)

            if status not in range(200, 400):
                self.stats.pages_failed += 1
                return

            self.stats.pages_crawled += 1
            ct = hdrs.get("Content-Type", "").lower()

            # ── Intel scan ───────────────────────────────────────────────────
            if any(t in ct for t in ("html", "text", "javascript", "json", "xml")):
                try:
                    txt = data.decode("utf-8", errors="replace")
                    for f_obj in self.intel.scan(url, txt):
                        await self._add_finding(f_obj)
                except Exception:
                    pass

            # ── Extract links ────────────────────────────────────────────────
            if any(t in ct for t in ("html", "text", "xml", "json")):
                try:
                    txt = data.decode("utf-8", errors="replace")
                    links, emails = extract_links(txt, url)

                    self._emails.update(emails)

                    for link in links:
                        ln = normalize(link)
                        if ln in self.bloom:   continue
                        if ln in self._visited: continue
                        if not in_scope(link, self.seed_base): continue
                        self.bloom.add(ln)
                        self.stats.urls_queued += 1
                        if is_file(link):
                            self.stats.files_found += 1
                            await self._queue.put((0, link, depth + 1, True))
                        else:
                            await self._queue.put((depth + 1, link, depth + 1, False))
                except Exception:
                    pass

            if depth > self.stats.depth_reached:
                self.stats.depth_reached = depth

        except Exception:
            self.stats.pages_failed += 1
        finally:
            self.stats.active_workers -= 1

    # ── Worker ────────────────────────────────────────────────────────────────
    async def _worker(self):
        while not self._shutdown:
            try:
                item = await asyncio.wait_for(self._queue.get(), timeout=8.0)
                _, url, depth, file_flag = item
                if file_flag:
                    await self._dl_file(url)
                else:
                    await self._crawl(url, depth)
                self._queue.task_done()
            except asyncio.TimeoutError:
                # Auto-stop: nothing left to process
                if self.stats.active_workers == 0 and self._queue.empty():
                    self._shutdown = True
                    break
            except Exception:
                pass

    # ── Write sensitive report ────────────────────────────────────────────────
    async def _write_report(self) -> str:
        path = os.path.join(self.outdir, "sensitive_findings.txt")
        lines = []
        W = 80
        lines.append("=" * W)
        lines.append("  CYFRIN CRAWLER v2.0 — SENSITIVE FINDINGS REPORT")
        lines.append(f"  Target  : {self.target}")
        lines.append(f"  Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"  Total   : {self.stats.findings_total}  "
                     f"(CRITICAL: {self.stats.findings_critical}  "
                     f"HIGH: {self.stats.findings_high})")
        lines.append("=" * W)
        lines.append("")

        if not self._findings:
            lines.append("  No sensitive findings detected.")
        else:
            ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            grouped: Dict[str, Dict[str, List[Finding]]] = {s: {} for s in ORDER}
            for f in self._findings:
                sev = f.severity if f.severity in ORDER else "LOW"
                grouped[sev].setdefault(f.category, []).append(f)

            for sev in ORDER:
                cats = grouped[sev]
                if not cats: continue
                total = sum(len(v) for v in cats.values())
                lines.append("─" * W)
                lines.append(f"  [{sev}]  ({total} findings)")
                lines.append("─" * W)
                lines.append("")
                for cat, flist in sorted(cats.items()):
                    lines.append(f"  ▶  {cat.upper()}  ({len(flist)})")
                    lines.append("")
                    for idx, f in enumerate(flist, 1):
                        lines.append(f"  [{idx:03d}]  {f.label}")
                        lines.append(f"         URL     : {f.url}")
                        lines.append(f"         Match   : {f.match[:200]}")
                        lines.append(f"         Context : {f.context[:300]}")
                        lines.append("")

        lines.append("=" * W)
        lines.append("  EMAILS FOUND")
        lines.append("─" * W)
        if self._emails:
            for e in sorted(self._emails): lines.append(f"  {e}")
        else:
            lines.append("  None")
        lines.append("")
        lines.append("=" * W)
        lines.append("  END OF REPORT")
        lines.append("=" * W)

        async with aiofiles.open(path, "w", encoding="utf-8") as fh:
            await fh.write("\n".join(lines))
        return path

    # ── Export results JSON ───────────────────────────────────────────────────
    async def _export_json(self) -> str:
        path = os.path.join(self.outdir, "results.json")
        data = {
            "meta": {
                "crawl_date": datetime.now().isoformat(),
                "target":     self.target,
                "stats": {
                    "pages_crawled":     self.stats.pages_crawled,
                    "files_downloaded":  self.stats.files_downloaded,
                    "bytes_downloaded":  self.stats.bytes_downloaded,
                    "emails_found":      len(self._emails),
                    "findings_total":    self.stats.findings_total,
                    "findings_critical": self.stats.findings_critical,
                    "findings_high":     self.stats.findings_high,
                    "depth_reached":     self.stats.depth_reached,
                    "elapsed":           self.stats.elapsed,
                },
            },
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "label":    f.label,
                    "url":      f.url,
                    "match":    f.match,
                }
                for f in self._findings
            ],
            "emails": sorted(self._emails),
        }
        async with aiofiles.open(path, "w", encoding="utf-8") as fh:
            await fh.write(json.dumps(data, indent=2, default=str))
        return path

    # ── Main run ──────────────────────────────────────────────────────────────
    async def run(self) -> Tuple[str, str]:
        self._session = await self._make_session()

        # Seed
        norm = normalize(self.target)
        self.bloom.add(norm)
        self.stats.urls_queued += 1
        await self._queue.put((0, self.target, 0, False))

        # Signal handlers
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, lambda: setattr(self, "_shutdown", True))
            except (NotImplementedError, OSError):
                pass

        workers = [asyncio.create_task(self._worker()) for _ in range(self.CONCURRENCY)]

        if RICH:
            with Live(self.dash.render(self.stats),
                      console=self.dash.console,
                      refresh_per_second=4,
                      screen=False) as live:
                self.dash._live = live
                while not self._shutdown:
                    live.update(self.dash.render(self.stats))
                    await asyncio.sleep(0.25)
                    if self._queue.empty() and self.stats.active_workers == 0:
                        self._shutdown = True
        else:
            while not self._shutdown:
                await asyncio.sleep(1)
                if self._queue.empty() and self.stats.active_workers == 0:
                    self._shutdown = True
                print(
                    f"\r[{self.stats.elapsed}] "
                    f"Pages:{self.stats.pages_crawled} "
                    f"Files:{self.stats.files_downloaded} "
                    f"Findings:{self.stats.findings_total} "
                    f"RPS:{self.stats.rps:.1f}",
                    end="", flush=True,
                )
            print()

        self._shutdown = True
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        await self._session.close()

        report_path  = await self._write_report()
        results_path = await self._export_json()
        return results_path, report_path


# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY PANEL
# ─────────────────────────────────────────────────────────────────────────────

def print_summary(console, spider: CyfrinCrawler, results: str, report: str):
    s = spider.stats
    t = Table(box=box.ROUNDED, show_header=False, border_style="bright_green", padding=(0, 2))
    t.add_column("k", style="bold cyan",    min_width=26)
    t.add_column("v", style="bright_white", min_width=20)

    t.add_row("📄  Pages Crawled",      f"[green]{s.pages_crawled}[/]")
    t.add_row("❌  Pages Failed",       f"[red]{s.pages_failed}[/]")
    t.add_row("📁  Files Downloaded",   f"[green]{s.files_downloaded}[/]")
    t.add_row("💾  Data Downloaded",    f"[magenta]{s.bytes_human}[/]")
    t.add_row("🌐  URLs Visited",       f"[white]{s.urls_visited}[/]")
    t.add_row("📊  Max Depth Reached",  f"[white]{s.depth_reached}[/]")
    t.add_row("📧  Emails Found",       f"[white]{len(spider._emails)}[/]")
    t.add_row("⏱   Time Elapsed",       f"[yellow]{s.elapsed}[/]")
    t.add_row("", "")
    crit_col = "bold red" if s.findings_critical > 0 else "dim"
    high_col = "red"      if s.findings_high > 0     else "dim"
    t.add_row("🔴  CRITICAL Findings",  f"[{crit_col}]{s.findings_critical}[/]")
    t.add_row("🟠  HIGH Findings",      f"[{high_col}]{s.findings_high}[/]")
    t.add_row("🔎  Total Findings",     f"[bright_white]{s.findings_total}[/]")
    t.add_row("", "")
    t.add_row("📂  Output Folder",      f"[yellow]{spider.outdir}/[/]")
    t.add_row("🚨  Sensitive Report",   f"[bold red]{report}[/]")
    t.add_row("📊  Results JSON",       f"[cyan]{results}[/]")

    console.print()
    console.print(Panel(t,
        title="[bold green]  ✅  CRAWL COMPLETE — AUTO STOPPED  [/bold green]",
        border_style="bright_green",
        padding=(1, 2),
    ))
    console.print()

    if s.findings_critical > 0:
        console.print(f"  [bold red]⚠  {s.findings_critical} CRITICAL findings! → {report}[/bold red]\n")
    elif s.findings_total > 0:
        console.print(f"  [yellow]⚠  {s.findings_total} findings detected → {report}[/yellow]\n")
    else:
        console.print("  [green]✓  No sensitive data detected.[/green]\n")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    console = Console() if RICH else None

    # ── Banner ────────────────────────────────────────────────────────────────
    if RICH:
        console.print(f"[bold red]{BANNER}[/bold red]")
        console.print(f"[bold white]{TAGLINE}[/bold white]\n")
    else:
        print(BANNER)
        print(TAGLINE + "\n")

    # ── Domain prompt — THE ONLY QUESTION ────────────────────────────────────
    if RICH:
        console.print(
            Panel.fit(
                "[bold white]  Target Configuration  [/bold white]",
                border_style="bright_red",
                padding=(0, 6),
            )
        )
        console.print()
        while True:
            console.print(
                "  [bold bright_red]►[/bold bright_red]"
                " [bold white]Enter Domain Name[/bold white]"
                " [dim](e.g. example.com)[/dim] : ",
                end="",
            )
            raw = input().strip()
            if raw: break
            console.print("  [red]  ✗  Cannot be empty.[/red]\n")
    else:
        while True:
            raw = input("  Enter Domain Name: ").strip()
            if raw: break

    # Normalize URL
    if not re.match(r'^https?://', raw):
        target_url = "https://" + raw
    else:
        target_url = raw

    parsed = urlparse(target_url)
    if not parsed.netloc:
        msg = "  Invalid domain. Exiting."
        if RICH: console.print(f"[bold red]{msg}[/bold red]")
        else: print(msg)
        sys.exit(1)

    outdir = main_name(raw)

    # ── Pre-launch info ───────────────────────────────────────────────────────
    if RICH:
        console.print()
        console.print(f"  [bold bright_red]►[/bold bright_red] [bold white]Target[/bold white]        : [cyan]{target_url}[/cyan]")
        console.print(f"  [bold bright_red]►[/bold bright_red] [bold white]Output Folder[/bold white] : [yellow]{outdir}/[/yellow]")
        console.print(f"  [bold bright_red]►[/bold bright_red] [bold white]Mode[/bold white]          : "
                      "[white]UNLIMITED depth[/white]  ·  "
                      "[white]AUTO-STOP[/white]  ·  "
                      "[white]Robots OFF[/white]  ·  "
                      "[white]All subdomains[/white]")
        console.print()
        console.rule("[bold bright_red]  Launching  [/bold bright_red]")
        console.print()
    else:
        print(f"\n  Target : {target_url}")
        print(f"  Output : {outdir}/")
        print(f"  Mode   : UNLIMITED depth · AUTO-STOP · all subdomains")
        print("─" * 60)

    # ── Run ───────────────────────────────────────────────────────────────────
    try:
        spider = CyfrinCrawler(target_url, outdir)
        results_path, report_path = asyncio.run(spider.run())

        if RICH:
            print_summary(console, spider, results_path, report_path)
        else:
            s = spider.stats
            print(f"\n✅ Done.")
            print(f"   Pages    : {s.pages_crawled}")
            print(f"   Files    : {s.files_downloaded}")
            print(f"   Findings : {s.findings_total}  (CRITICAL: {s.findings_critical})")
            print(f"   Report   : {report_path}")
            print(f"   Results  : {results_path}")

    except KeyboardInterrupt:
        if RICH: console.print("\n[bold red]  ✗ Interrupted.[/bold red]\n")
        else:    print("\n  Interrupted.")
        sys.exit(0)


if __name__ == "__main__":
    main()
