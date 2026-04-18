"""
skills/skill_loader.py — 動態 Skill 熱載入系統 (Phase 4D)
============================================================

設計目標：
  - 無需重啟 FastAPI 服務即可更新 SOP .md 檔案
  - mtime 型 LRU Cache：讀取 + 快取，修改後自動失效
  - 執行緒安全：所有公開方法均受 threading.RLock 保護
  - Graceful Degradation：檔案遺失時回退到嵌入式 fallback SOP
  - 可觀測性：提供完整的 registry API 供 /api/skills 端點使用

架構：
  SkillLoader（單例）
    ├── _load_with_mtime()   讀取 .md → 快取 (content, mtime, load_time)
    ├── load_skill()         公開取得介面（mtime 驗證，過期自動 reload）
    ├── reload_skill()       強制重載（不管 mtime）
    ├── reload_all()         強制重載全部
    └── get_registry()       列出所有已快取的 skill + 版本資訊

相容性：
  - 所有現有 Agent 的 _load_skill() 可無縫替換為
    skill_loader.load_skill(filename)
  - 新增 server.py API 端點使用 skill_loader.get_registry()

遵守：project_CONSTITUTION.md + AGENTS.md + HARNESS_ENGINEERING.md
"""

import logging
import os
import threading
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger("ThreatHunter.skill_loader")

# ── Skill 目錄定位 ───────────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).parent.parent
_SKILLS_DIR   = Path(__file__).parent  # skills/ 目錄本身

# ── 快取 TTL（以秒計）：已修改的檔案在此時間後強制 reload ─────────
# 設置為 0 代表每次都驗證 mtime（最即時但性能稍差）
# 設置為正數代表 stall 期間，TTL 內不 check mtime（高性能）
CACHE_TTL_SECONDS: float = float(os.getenv("SKILL_CACHE_TTL", "5.0"))

# ── 所有 skill 檔案的對應 fallback SOP ──────────────────────────
_FALLBACK_SOPS: dict[str, str] = {
    "threat_intel.md": """
# Skill: Threat Intel Scout (fallback)
## SOP
1. read_memory(agent_name="scout")
2. search_nvd 查詢每個套件
3. CVSS >= 7.0 → search_otx
4. 比對歷史標記 is_new
5. write_memory 寫入
6. 輸出純 JSON
""".strip(),
    "source_code_audit.md": """
# Skill: Source Code Audit (fallback)
## SOP
1. Identify imported packages from code
2. search_nvd for each package
3. Flag hardcoded secrets (OWASP A07)
4. write_memory, output JSON
""".strip(),
    "ai_security_audit.md": """
# Skill: AI Security Audit (fallback)
## SOP
1. Classify input: prompt injection / jailbreak / data poisoning
2. Map to OWASP LLM Top10
3. Rate severity 1-10
4. Output JSON (no CVE calls needed)
""".strip(),
    "config_audit.md": """
# Skill: Config Audit (fallback)
## SOP
1. Check for hardcoded secrets
2. Validate against CIS Benchmark
3. Flag misconfigurations
4. Output JSON
""".strip(),
}

_DEFAULT_FALLBACK = """
# Skill SOP (generic fallback)
Follow security analysis best practices.
Output structured JSON with findings.
Do not fabricate CVE IDs.
""".strip()


class _CacheEntry:
    """單一 Skill 的快取條目"""

    __slots__ = ("content", "mtime", "load_time", "filename", "size_bytes")

    def __init__(self, filename: str, content: str, mtime: float):
        self.filename   = filename
        self.content    = content
        self.mtime      = mtime          # 磁碟上的 mtime（float，Unix timestamp）
        self.load_time  = time.time()    # 本次 reload 的時間
        self.size_bytes = len(content.encode("utf-8"))


class SkillLoader:
    """
    執行緒安全的 Skill 熱載入器（單例推薦）。

    使用範例：
        from skills.skill_loader import skill_loader
        sop = skill_loader.load_skill("threat_intel.md")

    API：
        load_skill(filename)  → str   （快取 + 自動失效）
        reload_skill(filename) → str  （強制重載）
        reload_all()          → dict  （重載全部已快取）
        get_registry()        → dict  （列出所有快取內容）
        invalidate(filename)  → None  （移除單一快取條目）
        invalidate_all()      → None  （清空全部快取）
    """

    def __init__(self, skills_dir: Path | str | None = None):
        self._skills_dir = Path(skills_dir) if skills_dir else _SKILLS_DIR
        self._cache: dict[str, _CacheEntry] = {}
        self._lock = threading.RLock()
        logger.info("[SkillLoader] 初始化完成 | skills_dir=%s", self._skills_dir)

    # ══════════════════════════════════════════════════════════════
    # 核心讀取
    # ══════════════════════════════════════════════════════════════

    def _get_mtime(self, filepath: Path) -> Optional[float]:
        """取得檔案的 mtime（若不存在則回傳 None）"""
        try:
            return filepath.stat().st_mtime
        except (OSError, FileNotFoundError):
            return None

    def _read_file(self, filepath: Path) -> Optional[str]:
        """嘗試多種編碼讀取 .md 檔案，失敗回傳 None"""
        for enc in ("utf-8", "utf-8-sig", "latin-1"):
            try:
                content = filepath.read_text(encoding=enc).strip()
                if content:
                    return content
            except (OSError, UnicodeDecodeError):
                continue
        return None

    def _load_with_mtime(self, filename: str) -> _CacheEntry:
        """
        從磁碟讀取 skill 並建立快取條目。
        若讀取失敗，使用 fallback SOP 建立條目（mtime=-1 標識為 fallback）。
        """
        filepath = self._skills_dir / filename
        mtime = self._get_mtime(filepath)

        if mtime is not None:
            content = self._read_file(filepath)
            if content:
                logger.info("[SkillLoader] 載入: %s (%d chars)", filename, len(content))
                return _CacheEntry(filename, content, mtime)
            else:
                logger.warning("[SkillLoader] 檔案為空: %s，使用 fallback", filename)
        else:
            logger.warning("[SkillLoader] 找不到檔案: %s，使用 fallback", filename)

        # Fallback：使用嵌入式 SOP
        fallback_content = _FALLBACK_SOPS.get(filename, _DEFAULT_FALLBACK)
        return _CacheEntry(filename, fallback_content, -1.0)

    # ══════════════════════════════════════════════════════════════
    # 公開 API
    # ══════════════════════════════════════════════════════════════

    def load_skill(self, filename: str) -> str:
        """
        取得 Skill SOP 內容（快取優先，mtime 驗證自動失效）。

        邏輯：
          1. 若快取中無此檔 → 從磁碟載入 → 快取
          2. 若快取存在 + TTL 內 → 直接回傳（最高效）
          3. 若快取存在 + TTL 過期 → 驗證 mtime：
               mtime 不變 → 更新 load_time，繼續使用
               mtime 改變 → 重新從磁碟載入（熱載入！）
          4. fallback entry（mtime=-1）→ 每次重試磁碟確認是否已建立

        Args:
            filename: Skill .md 文件名（不含路徑），如 "threat_intel.md"

        Returns:
            str: Skill 文件內容（或 fallback SOP）
        """
        with self._lock:
            entry = self._cache.get(filename)

            # 情況 1：尚未快取 → 載入
            if entry is None:
                entry = self._load_with_mtime(filename)
                self._cache[filename] = entry
                return entry.content

            # 情況 2：TTL 內 → 直接回傳
            age = time.time() - entry.load_time
            if age < CACHE_TTL_SECONDS:
                return entry.content

            # 情況 3 / 4：TTL 過期，驗證 mtime
            current_mtime = self._get_mtime(self._skills_dir / filename)

            if current_mtime is None:
                # 檔案消失了 → 若是 fallback 就繼續用，否則切換 fallback
                if entry.mtime == -1.0:
                    entry.load_time = time.time()  # 刷新 TTL
                else:
                    logger.warning("[SkillLoader] 熱載入偵測：%s 已刪除，切換 fallback", filename)
                    entry = self._load_with_mtime(filename)  # 會走 fallback 路徑
                    self._cache[filename] = entry
                return entry.content

            if current_mtime == entry.mtime:
                # 檔案未更動 → 更新 load_time 刷新 TTL
                entry.load_time = time.time()
                return entry.content

            # 檔案已更新！熱載入
            logger.info(
                "[SkillLoader] 🔄 熱載入 %s (舊 mtime=%.3f → 新 mtime=%.3f)",
                filename, entry.mtime, current_mtime,
            )
            entry = self._load_with_mtime(filename)
            self._cache[filename] = entry
            return entry.content

    def reload_skill(self, filename: str) -> str:
        """
        強制重載指定 Skill（不管 mtime 和 TTL）。
        適用於：/api/skills/reload API 被呼叫時。

        Returns:
            str: 重新載入後的 Skill 內容
        """
        with self._lock:
            logger.info("[SkillLoader] 強制重載: %s", filename)
            entry = self._load_with_mtime(filename)
            self._cache[filename] = entry
            return entry.content

    def reload_all(self) -> dict[str, str]:
        """
        強制重載所有已快取的 Skill。

        Returns:
            dict[filename → new_content]（包含 fallback entry）
        """
        with self._lock:
            results = {}
            for filename in list(self._cache.keys()):
                entry = self._load_with_mtime(filename)
                self._cache[filename] = entry
                results[filename] = entry.content
            logger.info("[SkillLoader] 全部重載完成, %d 個 skill", len(results))
            return results

    def invalidate(self, filename: str) -> None:
        """移除單一快取條目（下次 load_skill 時重新讀取）"""
        with self._lock:
            removed = self._cache.pop(filename, None)
            if removed:
                logger.info("[SkillLoader] 快取失效: %s", filename)

    def invalidate_all(self) -> None:
        """清空全部快取（下次 load_skill 時重新讀取所有）"""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            logger.info("[SkillLoader] 全部快取清空 (%d 個)", count)

    def get_registry(self) -> dict:
        """
        回傳所有已快取的 Skill 狀態，供 /api/skills 端點使用。

        Returns:
            dict:
              {
                "skills_dir": str,
                "cache_ttl_seconds": float,
                "total": int,
                "skills": [
                  {
                    "filename": str,
                    "size_bytes": int,
                    "mtime": float,      # -1 = fallback SOP
                    "load_time": float,
                    "age_seconds": float,
                    "is_fallback": bool,
                    "content_preview": str  # 前 200 字元
                  }
                ]
              }
        """
        with self._lock:
            now = time.time()
            skills_list = []
            for filename, entry in self._cache.items():
                skills_list.append({
                    "filename":       filename,
                    "size_bytes":     entry.size_bytes,
                    "mtime":          entry.mtime,
                    "load_time":      entry.load_time,
                    "age_seconds":    round(now - entry.load_time, 2),
                    "is_fallback":    entry.mtime == -1.0,
                    "content_preview": entry.content[:200],
                })
            return {
                "skills_dir":        str(self._skills_dir),
                "cache_ttl_seconds": CACHE_TTL_SECONDS,
                "total":             len(skills_list),
                "skills":            skills_list,
            }

    def get_skill_content(self, filename: str) -> Optional[str]:
        """
        回傳已快取的 Skill 原始內容（若尚未快取則先載入）。
        供 /api/skills/{name} 端點使用。
        """
        return self.load_skill(filename)

    def list_available_skills(self) -> list[str]:
        """
        掃描 skills/ 目錄，回傳所有可用的 .md 檔案清單。
        （包含未快取的檔案）
        """
        try:
            return sorted(
                f.name for f in self._skills_dir.iterdir()
                if f.is_file() and f.suffix == ".md"
            )
        except OSError as e:
            logger.warning("[SkillLoader] 無法掃描 skills/ 目錄: %s", e)
            return list(_FALLBACK_SOPS.keys())

    def get_stats(self) -> dict:
        """
        回傳 SkillLoader 的效能統計。
        """
        with self._lock:
            return {
                "cached_skills":    len(self._cache),
                "fallback_count":   sum(1 for e in self._cache.values() if e.mtime == -1.0),
                "skills_dir":       str(self._skills_dir),
                "cache_ttl_seconds": CACHE_TTL_SECONDS,
            }


# ══════════════════════════════════════════════════════════════════
# 全域單例（供所有 Agent 使用的共享實例）
# ══════════════════════════════════════════════════════════════════

skill_loader = SkillLoader()


# ══════════════════════════════════════════════════════════════════
# 便利函式（向後相容 —— 取代 agents/ 中的 _load_skill()）
# ══════════════════════════════════════════════════════════════════

def load_skill(filename: str) -> str:
    """
    全域便利函式，等同於 skill_loader.load_skill(filename)。
    Agent 可直接 from skills.skill_loader import load_skill 使用。
    """
    return skill_loader.load_skill(filename)


def reload_skill(filename: str) -> str:
    """強制重載單一 Skill"""
    return skill_loader.reload_skill(filename)


def get_registry() -> dict:
    """取得所有 Skill 的快取狀態"""
    return skill_loader.get_registry()
