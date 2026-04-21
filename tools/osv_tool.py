# tools/osv_tool.py
# 功能：OSV.dev (Open Source Vulnerabilities) 精確套件漏洞查詢
# 架構定位：取代 NVD keywordSearch，提供 ecosystem-aware 精確查詢
#
# 為何用 OSV 而非 NVD keywordSearch：
#   NVD keywordSearch = 全文搜尋（search_nvd("eval") → CVE-1999 ColdFusion）
#   OSV.dev           = package + ecosystem 精確查詢（只返回該套件的漏洞）
#
# 佐證：
#   - OSV.dev 是 Google 開源項目，GitHub/Snyk/Dependabot 都使用此資料庫
#   - https://osv.dev/docs/ — "Precise package-ecosystem-version vulnerability queries"
#   - Trivy/Grype 的本地資料庫也基於 OSV schema
#
# 使用方式：
#   from tools.osv_tool import search_osv

import json
import os
import time
import hashlib
import logging
from datetime import datetime, timezone

import requests
from crewai.tools import tool

logger = logging.getLogger("ThreatHunter.osv_tool")

# ══════════════════════════════════════════════════════════════
# 常數
# ══════════════════════════════════════════════════════════════

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
REQUEST_TIMEOUT = 20
MAX_RETRIES = 2

# 快取設定
CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
CACHE_TTL = 3600 * 24  # 24 小時

# ── Ecosystem 對應表 ─────────────────────────────────────────
# OSV.dev 使用的生態系名稱（精確匹配）
# 來源：https://osv.dev/docs/#section/Querying-by-package
ECOSYSTEM_MAP: dict[str, str] = {
    # Node.js / npm
    "express": "npm", "axios": "npm", "lodash": "npm", "react": "npm",
    "vue": "npm", "angular": "npm", "webpack": "npm", "babel": "npm",
    "typescript": "npm", "node": "npm", "npm": "npm", "next": "npm",
    "nuxt": "npm", "nestjs": "npm", "fastify": "npm", "koa": "npm",
    "socket.io": "npm", "moment": "npm", "dayjs": "npm", "uuid": "npm",
    "dotenv": "npm", "cors": "npm", "helmet": "npm", "multer": "npm",
    "sequelize": "npm", "mongoose": "npm", "jsonwebtoken": "npm",
    "bcrypt": "npm", "bcryptjs": "npm", "passport": "npm",
    "body-parser": "npm", "morgan": "npm", "joi": "npm", "yup": "npm",
    "cheerio": "npm", "puppeteer": "npm", "playwright": "npm",
    "jest": "npm", "mocha": "npm", "chai": "npm", "sinon": "npm",
    # Python / PyPI
    "django": "PyPI", "flask": "PyPI", "fastapi": "PyPI",
    "requests": "PyPI", "urllib3": "PyPI", "pillow": "PyPI",
    "numpy": "PyPI", "pandas": "PyPI", "scipy": "PyPI",
    "sqlalchemy": "PyPI", "celery": "PyPI", "redis": "PyPI",
    "pydantic": "PyPI", "httpx": "PyPI", "aiohttp": "PyPI",
    "cryptography": "PyPI", "paramiko": "PyPI", "jinja2": "PyPI",
    "werkzeug": "PyPI", "gunicorn": "PyPI", "uvicorn": "PyPI",
    "boto3": "PyPI", "setuptools": "PyPI", "pip": "PyPI",
    "ansible": "PyPI", "scrapy": "PyPI", "twisted": "PyPI",
    # Java / Maven
    "log4j": "Maven", "spring": "Maven", "jackson": "Maven",
    "struts": "Maven", "hibernate": "Maven", "netty": "Maven",
    "commons-collections": "Maven", "commons-lang": "Maven",
    # Go
    "gin": "Go", "echo": "Go", "fiber": "Go", "gorm": "Go",
    # Ruby
    "rails": "RubyGems", "devise": "RubyGems", "nokogiri": "RubyGems",
    # Rust
    "tokio": "crates.io", "serde": "crates.io", "actix": "crates.io",
}

# 短名稱 → 正式套件名 對應（部分套件 OSV 使用不同名稱）
CANONICAL_NAME_MAP: dict[str, str] = {
    "log4j": "log4j-core",
    "spring": "spring-core",
    "node": "express",  # 避免 "node" 被誤查
}


def _detect_ecosystem(package_name: str) -> str:
    """根據套件名稱推斷 ecosystem。"""
    name = package_name.lower().strip()
    if name in ECOSYSTEM_MAP:
        return ECOSYSTEM_MAP[name]
    # 啟發式規則：
    if name.startswith("py") or name.endswith("-py"):
        return "PyPI"
    if "spring" in name or "apache" in name:
        return "Maven"
    # 預設 npm（因為本系統主要目標是 Node.js）
    return "npm"


def _get_canonical_name(package_name: str) -> str:
    """取得 OSV 使用的正式套件名。"""
    name = package_name.lower().strip()
    return CANONICAL_NAME_MAP.get(name, name)


def _get_cache_path(package_name: str) -> str:
    safe_name = hashlib.md5(package_name.encode()).hexdigest()[:12]
    return os.path.join(CACHE_DIR, f"osv_cache_{package_name}_{safe_name}.json")


def _read_cache(package_name: str) -> dict | None:
    cache_path = _get_cache_path(package_name)
    try:
        if os.path.exists(cache_path):
            with open(cache_path, "r", encoding="utf-8") as f:
                cached = json.load(f)
            if time.time() - cached.get("_cached_at", 0) < CACHE_TTL:
                logger.info("[OK] OSV cache hit: %s", package_name)
                return cached
    except (json.JSONDecodeError, IOError):
        pass
    return None


def _write_cache(package_name: str, data: dict) -> None:
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        data["_cached_at"] = time.time()
        with open(_get_cache_path(package_name), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except (IOError, PermissionError) as e:
        logger.warning("[WARN] OSV cache write failed: %s", e)


def _query_osv_api(package_name: str, ecosystem: str) -> dict | None:
    """
    呼叫 OSV.dev API，精確查詢套件漏洞。

    OSV API 格式（POST）：
      {"package": {"name": "express", "ecosystem": "npm"}}

    返回：{"vulns": [...]}
    """
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem,
        }
    }

    for attempt in range(MAX_RETRIES):
        try:
            logger.info("[QUERY] OSV %s/%s (attempt %d)", ecosystem, package_name, attempt + 1)
            response = requests.post(
                OSV_QUERY_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=REQUEST_TIMEOUT,
            )
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                logger.warning("[WARN] OSV API 429 (rate limited), waiting...")
                time.sleep(5)
            else:
                logger.warning("[WARN] OSV API %d: %s", response.status_code, response.text[:100])
                return None
        except requests.exceptions.Timeout:
            logger.warning("[WARN] OSV API timeout")
        except requests.exceptions.ConnectionError:
            logger.warning("[WARN] OSV API connection failed")
        except requests.exceptions.RequestException as e:
            logger.warning("[WARN] OSV API error: %s", e)
    return None


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


def _parse_osv_vuln(vuln: dict, package_name: str) -> dict | None:
    """
    解析單一 OSV vulnerability 條目。

    OSV 回應格式：
    {
      "id": "GHSA-xxxx-xxxx-xxxx" 或 "CVE-2024-xxxxx",
      "aliases": ["CVE-2024-xxxxx"],
      "summary": "...",
      "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/..."}],
      ...
    }
    """
    vuln_id = vuln.get("id", "")
    aliases = vuln.get("aliases", [])

    # 優先使用 CVE ID（alias 中的 CVE）
    cve_id = vuln_id
    for alias in aliases:
        if alias.startswith("CVE-"):
            cve_id = alias
            break

    # CVSS 分數解析
    cvss_score = 0.0
    severity = "LOW"
    for sev_item in vuln.get("severity", []):
        sev_type = sev_item.get("type", "")
        if "CVSS_V3" in sev_type:
            # CVSS string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            # 從 database_specific 或 ecosystem_specific 取分數
            pass
    # 從 database_specific 取 CVSS
    db_spec = vuln.get("database_specific", {})
    cvss_score = float(db_spec.get("cvss", {}).get("score", 0.0)) if isinstance(db_spec.get("cvss"), dict) else 0.0
    if cvss_score == 0.0:
        # 嘗試從 severity string 估算
        sev_str = db_spec.get("severity", "LOW")
        severity = sev_str.upper() if sev_str else "LOW"
        cvss_map = {"CRITICAL": 9.5, "HIGH": 8.0, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 2.0}
        cvss_score = cvss_map.get(severity, 2.0)
    else:
        severity = _severity_from_cvss(cvss_score)

    # 避免返回無意義的 CVE（非標準 ID 且沒有 CVE alias）
    if not cve_id.startswith("CVE-") and not cve_id.startswith("GHSA-"):
        return None

    summary = vuln.get("summary", "No description available")
    published = vuln.get("published", "")
    modified = vuln.get("modified", "")

    # 取出受影響版本
    affected_str = ""
    for aff in vuln.get("affected", []):
        ranges = aff.get("ranges", [])
        for r in ranges:
            for event in r.get("events", []):
                if "fixed" in event:
                    affected_str = f"< {event['fixed']}"
                    break
            if affected_str:
                break
        if affected_str:
            break

    # ── GHSA Severity（Phase 7.5）──────────────────────────
    # database_specific.severity = GitHub Advisory 的官方嚴重度
    # 例：{"severity": "HIGH", "cvss": {...}}
    ghsa_severity = db_spec.get("severity", "").upper()
    if ghsa_severity not in ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"):
        # 嘗試從 osv_id 判斷（GHSA- 前綴代表 GitHub Advisory）
        ghsa_severity = severity if vuln_id.startswith("GHSA-") else "UNKNOWN"

    return {
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "severity": severity,
        "description": summary[:400],
        "affected_versions": affected_str,
        "package": package_name,
        "source": "OSV",
        "osv_id": vuln_id,
        "published": published[:10] if published else "",
        "is_new": True,
        # Phase 7.5：GHSA 維度資料，供 Intel Fusion 直接使用
        "ghsa_severity": ghsa_severity,
    }


def _search_osv_impl(package_name: str) -> str:
    """search_osv 的核心實作。"""
    name = package_name.strip().lower().split()[0]  # 去掉版本號
    canonical = _get_canonical_name(name)
    ecosystem = _detect_ecosystem(name)

    # 快取 key：用底線分隔避免 / 在 Windows 路徑中出錯
    cache_key = f"{ecosystem}_{canonical}"
    cached = _read_cache(cache_key)
    if cached:
        return json.dumps(cached, ensure_ascii=False)

    # 2. 呼叫 OSV API
    raw = _query_osv_api(canonical, ecosystem)

    if raw is not None:
        vulns_raw = raw.get("vulns", [])
        parsed = []
        for v in vulns_raw[:15]:  # 最多取 15 個
            result = _parse_osv_vuln(v, canonical)
            if result:
                parsed.append(result)

        output = {
            "package": canonical,
            "ecosystem": ecosystem,
            "count": len(parsed),
            "vulnerabilities": parsed,
            "source": "OSV",
            "query_time": datetime.now(timezone.utc).isoformat(),
        }
        _write_cache(cache_key, output)
        logger.info("[OK] OSV query: %s/%s -> %d vulns", ecosystem, canonical, len(parsed))
        return json.dumps(output, ensure_ascii=False)

    # 3. 降級：回傳空結果（不 crash）
    logger.warning("[WARN] OSV API unavailable for: %s/%s", ecosystem, canonical)
    fallback = {
        "package": canonical,
        "ecosystem": ecosystem,
        "count": 0,
        "vulnerabilities": [],
        "source": "OSV",
        "error": f"OSV API unavailable for {ecosystem}/{canonical}",
    }
    return json.dumps(fallback, ensure_ascii=False)


def search_osv_batch(package_names: list[str]) -> dict[str, list]:
    """
    OSV Batch API：同時查詢多個套件，減少延遲（比逐一查詢快 N 倍）。

    API：POST https://api.osv.dev/v1/querybatch
    格式：{"queries": [{"package": {"name": "...", "ecosystem": "..."}}, ...]}
    回應：{"results": [{"vulns": [...]}, ...]} （順序對應 queries）

    供 Scout/Intel Fusion 批量查詢使用。

    Returns:
        {package_name: [vuln_dict, ...], ...}
    """
    if not package_names:
        return {}

    # 先查快取，只發 API 請求給未命中的
    results: dict[str, list] = {}
    uncached = []

    for pkg in package_names:
        name = pkg.strip().lower().split()[0]
        canonical = _get_canonical_name(name)
        ecosystem = _detect_ecosystem(name)
        cache_key = f"{ecosystem}_{canonical}"
        cached = _read_cache(cache_key)
        if cached:
            results[name] = cached.get("vulnerabilities", [])
            logger.info("[OK] OSV batch cache hit: %s", name)
        else:
            uncached.append((name, canonical, ecosystem))

    if not uncached:
        return results

    # 批量 API 請求
    queries = [
        {"package": {"name": canonical, "ecosystem": ecosystem}}
        for _, canonical, ecosystem in uncached
    ]
    payload = {"queries": queries}

    try:
        logger.info("[QUERY] OSV batch: %d packages", len(queries))
        response = requests.post(
            OSV_BATCH_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code == 200:
            batch_results = response.json().get("results", [])
            for i, (orig_name, canonical, ecosystem) in enumerate(uncached):
                if i >= len(batch_results):
                    break
                vulns_raw = batch_results[i].get("vulns", [])
                parsed = [r for r in
                          (_parse_osv_vuln(v, canonical) for v in vulns_raw[:15])
                          if r]
                results[orig_name] = parsed
                # 寫快取
                cache_key = f"{ecosystem}_{canonical}"
                _write_cache(cache_key, {
                    "package": canonical,
                    "ecosystem": ecosystem,
                    "count": len(parsed),
                    "vulnerabilities": parsed,
                    "source": "OSV",
                    "query_time": datetime.now(timezone.utc).isoformat(),
                })
                logger.info("[OK] OSV batch: %s/%s -> %d vulns", ecosystem, canonical, len(parsed))
        else:
            logger.warning("[WARN] OSV batch API %d, falling back to single queries", response.status_code)
            # fallback: 逐一查詢
            for orig_name, canonical, ecosystem in uncached:
                single_raw = _query_osv_api(canonical, ecosystem)
                if single_raw:
                    parsed = [r for r in
                              (_parse_osv_vuln(v, canonical) for v in single_raw.get("vulns", [])[:15])
                              if r]
                    results[orig_name] = parsed
                else:
                    results[orig_name] = []
    except Exception as e:
        logger.warning("[WARN] OSV batch failed: %s", e)
        for orig_name, _, _ in uncached:
            results.setdefault(orig_name, [])

    return results


# ══════════════════════════════════════════════════════════════
# CrewAI @tool 裝飾器（延遲載入，與 nvd_tool.py 一致）
# ══════════════════════════════════════════════════════════════

class _Loader:
    _instance = None

    def __init__(self):
        self._tool = None

    def _load(self):
        if self._tool is None:
            @tool("search_osv")
            def search_osv(package_name: str) -> str:
                """查詢 OSV.dev (Open Source Vulnerabilities) 資料庫中套件的已知漏洞。

                使用 ecosystem-aware 精確查詢，不會返回無關生態系的 CVE。
                相比 NVD keywordSearch，精確度大幅提升。

                建議優先使用此工具，NVD 作為補充。
                """
                return _search_osv_impl(package_name)
            self._tool = search_osv
        return self._tool

    @property
    def search_osv(self):
        return self._load()


_loader = _Loader()


def __getattr__(name: str):
    if name == "search_osv":
        return _loader.search_osv
    raise AttributeError(f"module 'tools.osv_tool' has no attribute {name!r}")
